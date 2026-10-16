//! TLS-only directory credential connector. Registry/portal activation is separate.
use super::{
    ProviderId, ProviderIdentity,
    credentials::{CredentialError, CredentialKind, CredentialProvider, PasswordInput},
};
use crate::crypto::Secret;
use anyhow::{Result, ensure};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectEncoding {
    #[default]
    Text,
    BinaryHex,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    #[serde(default)]
    pub starttls: bool,
    pub ca: PathBuf,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password_env: String,
    pub username_attribute: String,
    pub subject_attribute: String,
    #[serde(default)]
    pub subject_encoding: SubjectEncoding,
    pub timeout_ms: u64,
}
fn attribute(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.endpoint)?;
        ensure!(
            (url.scheme() == "ldaps" && !self.starttls)
                || (url.scheme() == "ldap" && self.starttls),
            "LDAP requires explicit TLS"
        );
        ensure!(
            url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/")
                && url.port() != Some(0),
            "invalid LDAP endpoint"
        );
        ensure!(self.ca.is_absolute(), "LDAP CA must be absolute");
        for dn in [&self.base_dn, &self.bind_dn] {
            ensure!(
                !dn.is_empty() && dn.len() <= 2048 && !dn.chars().any(char::is_control),
                "invalid LDAP DN"
            );
        }
        ensure!(
            attribute(&self.username_attribute) && attribute(&self.subject_attribute),
            "invalid LDAP attribute"
        );
        ensure!(
            !self.bind_password_env.is_empty()
                && self.bind_password_env.len() <= 128
                && self
                    .bind_password_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid LDAP secret reference"
        );
        ensure!(
            (1..=2000).contains(&self.timeout_ms),
            "LDAP deadline must be 1..2000 ms"
        );
        Ok(())
    }
}
fn immutable_subject(
    entry: &SearchEntry,
    attribute: &str,
    encoding: SubjectEncoding,
) -> Result<String, CredentialError> {
    let text: Vec<_> = entry
        .attrs
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .collect();
    let binary: Vec<_> = entry
        .bin_attrs
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .collect();
    if text.len() + binary.len() != 1 {
        return Err(CredentialError::Unavailable);
    }
    let namespace = attribute.to_ascii_lowercase();
    match encoding {
        SubjectEncoding::Text => {
            let values = text
                .first()
                .map(|(_, values)| *values)
                .ok_or(CredentialError::Unavailable)?;
            let value = values
                .first()
                .filter(|value| {
                    values.len() == 1
                        && !value.is_empty()
                        && value.len() <= 128
                        && !value.chars().any(char::is_control)
                })
                .ok_or(CredentialError::Unavailable)?;
            Ok(format!("t:{namespace}:{value}"))
        }
        SubjectEncoding::BinaryHex => {
            let bytes = if let Some((_, values)) = binary.first() {
                if values.len() != 1 {
                    return Err(CredentialError::Unavailable);
                }
                values[0].as_slice()
            } else {
                let values = text[0].1;
                if values.len() != 1 {
                    return Err(CredentialError::Unavailable);
                }
                values[0].as_bytes()
            };
            if bytes.is_empty() || bytes.len() > 64 {
                return Err(CredentialError::Unavailable);
            }
            use std::fmt::Write;
            let mut subject = format!("b:{namespace}:");
            for byte in bytes {
                write!(&mut subject, "{byte:02x}").map_err(|_| CredentialError::Unavailable)?;
            }
            Ok(subject)
        }
    }
}
/// The LDAP group spec of a stored provider configuration: `groups.ldap`, or
/// the default (`memberOf`) when `groups` is present without it.
pub(crate) fn ldap_groups_of(
    configuration: &serde_json::Value,
) -> Option<crate::groups::LdapGroups> {
    crate::groups::ProviderGroups::of_row(configuration).map(|g| g.ldap.unwrap_or_default())
}
pub struct LdapProvider {
    id: ProviderId,
    config: Config,
    /// `providers[].groups.ldap` of the row, when the provider syncs groups.
    groups: Option<crate::groups::LdapGroups>,
    bind_password: Secret,
    tls: Arc<rustls::ClientConfig>,
    capacity: tokio::sync::Semaphore,
    circuit: Arc<crate::auth_gateway::breaker::Circuit>,
}
struct Connection {
    ldap: Ldap,
    driver: tokio::task::JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl LdapProvider {
    pub fn compile(
        id: ProviderId,
        config: Config,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        Self::compile_material(id, config, env, None).map(|(provider, _)| provider)
    }
    pub(crate) fn compile_material(
        id: ProviderId,
        config: Config,
        env: &dyn Fn(&str) -> Option<String>,
        material: Option<(&super::material::Key, &crate::store::ProviderRow)>,
    ) -> Result<(Self, Option<super::material::Fingerprint>)> {
        config.validate()?;
        let password = env(&config.bind_password_env)
            .ok_or_else(|| anyhow::anyhow!("LDAP secret reference unavailable"))?;
        ensure!(
            !password.is_empty() && password.len() <= 4096,
            "invalid LDAP service credential"
        );
        use std::{io::Read, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&config.ca)?;
        ensure!(file.metadata()?.is_file(), "LDAP CA must be regular");
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "LDAP CA exceeds bound");
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut bytes.as_slice()) {
            ensure!(roots.len() < 64, "LDAP CA count exceeds bound");
            roots.add(certificate?)?;
        }
        ensure!(!roots.is_empty(), "LDAP CA is empty");
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.enable_early_data = false;
        let fingerprint = material.and_then(|(key, row)| {
            let mut builder = key.start(row)?;
            builder.part(b"ldap-effective", &serde_json::to_vec(&config).ok()?);
            builder.part(b"ldap-bind-password", password.as_bytes());
            // These SAME validated bytes just built these TLS roots; no reopen.
            builder.part(b"ldap-ca", &bytes);
            Some(builder.finish())
        });
        Ok((
            Self {
                id,
                config,
                groups: None,
                bind_password: Secret::new(password),
                tls: Arc::new(tls),
                capacity: tokio::sync::Semaphore::new(64),
                circuit: crate::auth_gateway::breaker::Circuit::new(3, 30_000)
                    .expect("constant circuit bounds"),
            },
            fingerprint,
        ))
    }
    /// Sync groups as `groups` says (from the row's `groups.ldap`, or the
    /// `member_of` default when the row has a `groups` section without one).
    pub fn with_groups(mut self, groups: Option<crate::groups::LdapGroups>) -> Self {
        self.groups = groups;
        self
    }

    /// The person's groups, read with the service bind on `ldap`: the entry's
    /// `memberOf` values, or the group entries whose member attribute holds
    /// `dn`. `None` when the directory could not answer completely (the
    /// sync then changes nothing).
    async fn groups_of(
        &self,
        ldap: &mut Ldap,
        dn: &str,
        member_of: &[String],
    ) -> Option<Vec<super::types::RawGroup>> {
        let spec = self.groups.as_ref()?;
        match spec.mode {
            crate::groups::LdapGroupMode::MemberOf => Some(
                member_of
                    .iter()
                    .take(crate::groups::MAX_RAW_VALUES + 1)
                    .filter_map(|value| group_from_dn(value, None))
                    .collect(),
            ),
            crate::groups::LdapGroupMode::Search => {
                let filter = format!(
                    "(&(objectClass={})({}={}))",
                    spec.object_class,
                    spec.member_attribute,
                    ldap3::ldap_escape(dn)
                );
                let base = spec
                    .search_base_dn
                    .as_deref()
                    .unwrap_or(&self.config.base_dn);
                let mut options = SearchOptions::new();
                options.sizelimit =
                    i32::try_from(crate::groups::MAX_RAW_VALUES + 1).unwrap_or(4097);
                options.timelimit = 2;
                let mut search = ldap
                    .with_search_options(options)
                    .streaming_search(
                        base,
                        Scope::Subtree,
                        &filter,
                        [spec.name_attribute.as_str()],
                    )
                    .await
                    .ok()?;
                let mut out = Vec::new();
                while let Some(entry) = search.next().await.ok()? {
                    if entry.is_ref() || entry.is_intermediate() {
                        continue;
                    }
                    let entry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        SearchEntry::construct(entry)
                    }))
                    .ok()?;
                    let name = entry
                        .attrs
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(&spec.name_attribute))
                        .and_then(|(_, v)| v.first().cloned());
                    if let Some(g) = group_from_dn(&entry.dn, name) {
                        out.push(g);
                    }
                    if out.len() > crate::groups::MAX_RAW_VALUES {
                        break;
                    }
                }
                let result = search.finish().await;
                // A size-limited answer is incomplete: never applied.
                if result.rc != 0 || !result.refs.is_empty() {
                    return None;
                }
                Some(out)
            }
        }
    }

    /// The groups of the person whose immutable subject is `subject` (the
    /// periodic sync), with the service bind only. `Ok(Some(vec![]))` when
    /// the person no longer exists in the directory.
    async fn lookup_groups(
        &self,
        subject: &str,
    ) -> Result<Option<Vec<super::types::RawGroup>>, CredentialError> {
        let Some(spec) = self.groups.clone() else {
            return Ok(None);
        };
        let Some(filter) = subject_filter(
            subject,
            &self.config.subject_attribute,
            self.config.subject_encoding,
        ) else {
            return Ok(None);
        };
        let mut lookup = self.connect().await?;
        let bound = lookup
            .ldap
            .simple_bind(&self.config.bind_dn, self.bind_password.expose())
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        if bound.rc != 0 || !bound.refs.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        let mut options = SearchOptions::new();
        options.sizelimit = 2;
        options.timelimit = 2;
        let (entries, result) = lookup
            .ldap
            .with_search_options(options)
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                [spec.member_of_attribute.as_str()],
            )
            .await
            .map_err(|_| CredentialError::Unavailable)?
            .success()
            .map_err(|_| CredentialError::Unavailable)
            .map(|(e, r)| (e, r))?;
        if !result.refs.is_empty() || entries.len() > 1 {
            return Err(CredentialError::Unavailable);
        }
        let Some(entry) = entries.into_iter().next() else {
            return Ok(Some(Vec::new()));
        };
        let entry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SearchEntry::construct(entry)
        }))
        .map_err(|_| CredentialError::Unavailable)?;
        let member_of = attribute_values(&entry, &spec.member_of_attribute);
        let groups = self
            .groups_of(&mut lookup.ldap, &entry.dn, &member_of)
            .await;
        groups.map(Some).ok_or(CredentialError::Unavailable)
    }

    async fn connect(&self) -> Result<Connection, CredentialError> {
        let settings = LdapConnSettings::new()
            .set_config(self.tls.clone())
            .set_starttls(self.config.starttls)
            .set_conn_timeout(Duration::from_millis(self.config.timeout_ms));
        let (connection, ldap) = LdapConnAsync::with_settings(settings, &self.config.endpoint)
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        let driver = tokio::spawn(async move {
            let _ = connection.drive().await;
        });
        Ok(Connection { ldap, driver })
    }
    async fn verify(&self, input: PasswordInput<'_>) -> Result<ProviderIdentity, CredentialError> {
        let mut lookup = self.connect().await?;
        let bound = lookup
            .ldap
            .simple_bind(&self.config.bind_dn, self.bind_password.expose())
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        if bound.rc != 0 || !bound.refs.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        let filter = format!(
            "({}={})",
            self.config.username_attribute,
            ldap3::ldap_escape(input.username())
        );
        let mut options = SearchOptions::new();
        options.sizelimit = 2;
        options.timelimit = 2;
        let mut attributes = vec![self.config.subject_attribute.as_str()];
        if let Some(g) = &self.groups
            && g.mode == crate::groups::LdapGroupMode::MemberOf
        {
            attributes.push(g.member_of_attribute.as_str());
        }
        let mut search = lookup
            .ldap
            .with_search_options(options)
            .streaming_search(&self.config.base_dn, Scope::Subtree, &filter, attributes)
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        let mut selected = None;
        while let Some(entry) = search
            .next()
            .await
            .map_err(|_| CredentialError::Unavailable)?
        {
            if selected.is_some() || entry.is_ref() || entry.is_intermediate() {
                return Err(CredentialError::Invalid);
            }
            let entry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                SearchEntry::construct(entry)
            }))
            .map_err(|_| CredentialError::Unavailable)?;
            if entry.dn.is_empty()
                || entry.dn.len() > 2048
                || entry.dn.chars().any(char::is_control)
            {
                return Err(CredentialError::Unavailable);
            }
            let subject = immutable_subject(
                &entry,
                &self.config.subject_attribute,
                self.config.subject_encoding,
            )?;
            let member_of = self
                .groups
                .as_ref()
                .map(|g| attribute_values(&entry, &g.member_of_attribute))
                .unwrap_or_default();
            selected = Some((entry.dn, subject, member_of));
        }
        let result = search.finish().await;
        if result.rc != 0 || !result.refs.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        let (dn, subject, member_of) = selected.ok_or(CredentialError::Invalid)?;
        drop(search);
        // Groups are read with the service bind before the user bind; they
        // are applied only after the password is verified.
        let groups = if self.groups.is_some() {
            self.groups_of(&mut lookup.ldap, &dn, &member_of).await
        } else {
            None
        };
        drop(lookup);
        // Never pool a user-bound connection with another user or with service lookups.
        let mut user = self.connect().await?;
        let result = user
            .ldap
            .simple_bind(&dn, input.password().expose())
            .await
            .map_err(|_| CredentialError::Unavailable)?;
        if result.rc == 49 {
            return Err(CredentialError::Invalid);
        }
        if result.rc != 0 || !result.refs.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        Ok(ProviderIdentity {
            subject,
            email: None,
            email_verified: false,
            email_authoritative: false,
            name: None,
            username: None,
            picture: None,
            raw_claims: serde_json::json!({}),
            auth_time: None,
            groups,
        })
    }
}

/// Every value of `attribute` (case-insensitive name) as text.
fn attribute_values(entry: &SearchEntry, attribute: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(attribute))
        .flat_map(|(_, v)| v.iter().cloned())
        .take(crate::groups::MAX_RAW_VALUES + 1)
        .collect()
}

/// A group from its DN: the key is the DN with ASCII letters lower-cased and
/// spaces around separators removed (DNs compare case-insensitively in the
/// common schemas); the name is `name`, else the first RDN's value.
pub(crate) fn group_from_dn(dn: &str, name: Option<String>) -> Option<super::types::RawGroup> {
    let dn = dn.trim();
    if dn.is_empty() || dn.len() > crate::groups::MAX_KEY_BYTES || dn.chars().any(char::is_control)
    {
        return None;
    }
    let mut key = String::with_capacity(dn.len());
    let mut escaped = false;
    for ch in dn.chars() {
        if escaped {
            key.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                key.push(ch);
                escaped = true;
            }
            ',' | '=' | '+' => {
                while key.ends_with(' ') {
                    key.pop();
                }
                key.push(ch);
            }
            ' ' if key.ends_with([',', '=', '+']) => {}
            c => key.push(c.to_ascii_lowercase()),
        }
    }
    let name = name.filter(|n| !n.trim().is_empty()).or_else(|| {
        // The first RDN's value, unescaped up to the first unescaped comma.
        let (_, rest) = dn.split_once('=')?;
        let mut out = String::new();
        let mut esc = false;
        for ch in rest.chars() {
            if esc {
                out.push(ch);
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == ',' || ch == '+' {
                break;
            } else {
                out.push(ch);
            }
        }
        let out = out.trim().to_string();
        (!out.is_empty()).then_some(out)
    })?;
    Some(super::types::RawGroup { key, name })
}

/// The search filter that finds the entry of a stored subject
/// (`t:<attr>:<value>` or `b:<attr>:<hex>`) under the configured attribute.
fn subject_filter(subject: &str, attribute: &str, encoding: SubjectEncoding) -> Option<String> {
    let namespace = attribute.to_ascii_lowercase();
    match encoding {
        SubjectEncoding::Text => {
            let value = subject
                .strip_prefix("t:")?
                .strip_prefix(namespace.as_str())?
                .strip_prefix(':')?;
            (!value.is_empty()).then(|| format!("({attribute}={})", ldap3::ldap_escape(value)))
        }
        SubjectEncoding::BinaryHex => {
            let hex = subject
                .strip_prefix("b:")?
                .strip_prefix(namespace.as_str())?
                .strip_prefix(':')?;
            if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let mut value = String::with_capacity(hex.len() * 3 / 2);
            for pair in hex.as_bytes().chunks(2) {
                value.push('\\');
                value.push(pair[0] as char);
                value.push(pair[1] as char);
            }
            Some(format!("({attribute}={value})"))
        }
    }
}
#[async_trait::async_trait]
impl CredentialProvider for LdapProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn kind(&self) -> CredentialKind {
        CredentialKind::Ldap
    }
    fn enabled(&self) -> bool {
        true
    }
    fn matches_configuration(&self, configuration: &serde_json::Value) -> bool {
        configuration
            .get("ldap")
            .cloned()
            .and_then(|value| serde_json::from_value::<Config>(value).ok())
            .is_some_and(|config| config == self.config)
            && ldap_groups_of(configuration) == self.groups
    }
    async fn directory_groups(
        &self,
        subject: &str,
    ) -> Result<Option<Vec<super::types::RawGroup>>, CredentialError> {
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| CredentialError::Unavailable)?;
        let lease = self.circuit.admit().ok_or(CredentialError::Unavailable)?;
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.lookup_groups(subject),
        )
        .await
        .unwrap_or(Err(CredentialError::Unavailable));
        lease.finish(matches!(result, Err(CredentialError::Unavailable)));
        result
    }
    async fn verify_password(
        &self,
        input: PasswordInput<'_>,
    ) -> Result<ProviderIdentity, CredentialError> {
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| CredentialError::Unavailable)?;
        let lease = self.circuit.admit().ok_or(CredentialError::Unavailable)?;
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.verify(input),
        )
        .await
        .unwrap_or(Err(CredentialError::Unavailable));
        lease.finish(matches!(result, Err(CredentialError::Unavailable)));
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_identity_is_stable_and_namespaced_without_text_collision() {
        let mut entry = SearchEntry {
            dn: "uid=owned,dc=example,dc=test".into(),
            attrs: Default::default(),
            bin_attrs: Default::default(),
        };
        entry
            .bin_attrs
            .insert("objectGUID".into(), vec![vec![0, 1, 255]]);
        assert_eq!(
            immutable_subject(&entry, "objectguid", SubjectEncoding::BinaryHex).unwrap(),
            "b:objectguid:0001ff"
        );
        assert!(immutable_subject(&entry, "objectguid", SubjectEncoding::Text).is_err());
        entry.bin_attrs.clear();
        entry.attrs.insert("objectGUID".into(), vec!["abc".into()]);
        assert_eq!(
            immutable_subject(&entry, "objectguid", SubjectEncoding::BinaryHex).unwrap(),
            "b:objectguid:616263"
        );
        assert_eq!(
            immutable_subject(&entry, "objectguid", SubjectEncoding::Text).unwrap(),
            "t:objectguid:abc"
        );
        entry
            .attrs
            .insert("OBJECTGUID".into(), vec!["different".into()]);
        assert!(immutable_subject(&entry, "objectguid", SubjectEncoding::BinaryHex).is_err());
    }
    #[tokio::test]
    #[ignore = "requires the owned OpenLDAP fixture; run tools/owned_ldap_smoke.py"]
    async fn owned_ldaps_authenticates_immutable_identity_and_rejects_bad_credentials_and_ca() {
        let endpoint = std::env::var("OWNED_LDAP_ENDPOINT").unwrap();
        let password = Secret::new(std::env::var("OWNED_LDAP_USER_PASSWORD").unwrap());
        let config = Config {
            endpoint,
            starttls: std::env::var("OWNED_LDAP_STARTTLS").is_ok_and(|value| value == "1"),
            ca: std::env::var("OWNED_LDAP_CA").unwrap().into(),
            base_dn: "dc=example,dc=test".into(),
            bind_dn: "cn=reader,dc=example,dc=test".into(),
            bind_password_env: "OWNED_LDAP_BIND_KEY".into(),
            username_attribute: "uid".into(),
            subject_attribute: "entryUUID".into(),
            subject_encoding: SubjectEncoding::Text,
            timeout_ms: 2000,
        };
        let env = |name: &str| std::env::var(name).ok();
        let provider =
            LdapProvider::compile(ProviderId::new("owned-directory"), config.clone(), &env)
                .unwrap();
        assert!(provider.matches_configuration(&serde_json::json!({"ldap":config})));
        let mut changed = config.clone();
        changed.base_dn = "dc=other,dc=test".into();
        assert!(!provider.matches_configuration(&serde_json::json!({"ldap":changed})));
        let first = provider
            .verify_password(PasswordInput::new("alice", &password).unwrap())
            .await
            .unwrap();
        let second = provider
            .verify_password(PasswordInput::new("alice", &password).unwrap())
            .await
            .unwrap();
        assert_eq!(first.subject, second.subject);
        assert_ne!(first.subject, "alice");
        assert!(first.subject.starts_with("t:entryuuid:"));
        assert_eq!(first.subject.len(), 48);
        assert!(!first.email_verified && !first.email_authoritative && first.auth_time.is_none());
        let mut binary = config.clone();
        binary.subject_attribute = "jpegPhoto".into();
        binary.subject_encoding = SubjectEncoding::BinaryHex;
        let binary_provider =
            LdapProvider::compile(ProviderId::new("owned-binary-directory"), binary, &env).unwrap();
        let binary_identity = binary_provider
            .verify_password(PasswordInput::new("alice", &password).unwrap())
            .await
            .unwrap();
        assert_eq!(binary_identity.subject, "b:jpegphoto:0001ff");
        let authenticated = crate::provider::credentials::authenticate_password(
            &provider,
            PasswordInput::new("alice", &password).unwrap(),
            &crate::crypto::SystemClock,
        )
        .await
        .unwrap();
        assert_eq!(authenticated.identity().subject, first.subject);
        assert_eq!(
            authenticated.principal_kind(),
            crate::auth_gateway::PrincipalKind::Human
        );
        assert_eq!(authenticated.aal(), crate::session::types::Aal::One);
        assert_eq!(
            authenticated.auth_time_source(),
            crate::store::types::AuthTimeSource::HopaeCompletion
        );
        let row = crate::store::types::ProviderRow {
            provider_id: ProviderId::new("registered-directory"),
            kind: super::super::ProviderKind::Ldap,
            display_name: "Owned directory".into(),
            enabled: true,
            managed_by: crate::store::types::ManagedBy::File,
            deleted_at: None,
            sort_order: 0,
            config: serde_json::json!({"ldap":config}),
            client_secret_env: None,
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
        };
        let registry = super::super::Registry::from_snapshot(
            &[row],
            &env,
            Arc::new(crate::crypto::SystemClock),
            None,
        );
        assert!(
            registry
                .get(&ProviderId::new("registered-directory"))
                .is_none()
        );
        let registered = registry
            .credential(&ProviderId::new("registered-directory"))
            .unwrap();
        assert!(registered.enabled());
        let result = crate::provider::credentials::authenticate_password(
            registered.as_ref(),
            PasswordInput::new("alice", &password).unwrap(),
            &crate::crypto::SystemClock,
        )
        .await
        .unwrap();
        assert_eq!(result.identity().subject, first.subject);
        let wrong = Secret::new("owned-wrong-password".into());
        assert!(matches!(
            provider
                .verify_password(PasswordInput::new("alice", &wrong).unwrap())
                .await,
            Err(CredentialError::Invalid)
        ));
        assert!(matches!(
            provider
                .verify_password(PasswordInput::new("missing", &password).unwrap())
                .await,
            Err(CredentialError::Invalid)
        ));
        assert!(matches!(
            provider
                .verify_password(PasswordInput::new("alice*)(uid=*)", &password).unwrap())
                .await,
            Err(CredentialError::Invalid)
        ));
        assert!(matches!(
            provider
                .verify_password(PasswordInput::new("duplicated", &password).unwrap())
                .await,
            Err(CredentialError::Invalid)
        ));
        assert_eq!(
            provider.circuit.state(),
            Some(crate::auth_gateway::breaker::State::Closed)
        );
        for name in [
            "OWNED_LDAP_OVERSIZE",
            "OWNED_LDAP_DEEP",
            "OWNED_LDAP_EMPTY",
            "OWNED_LDAP_RESULT",
            "OWNED_LDAP_CONTROL",
            "OWNED_LDAP_WRONG_BIND",
            "OWNED_LDAP_WRONG_SEARCH",
            "OWNED_LDAP_WRONG_RESULT",
            "OWNED_LDAP_FLOOD",
        ] {
            let mut malicious = config.clone();
            malicious.endpoint = std::env::var(name).unwrap();
            malicious.starttls = false;
            let malicious =
                LdapProvider::compile(ProviderId::new("malicious-owned-peer"), malicious, &env)
                    .unwrap();
            let started = std::time::Instant::now();
            assert!(matches!(
                malicious
                    .verify_password(PasswordInput::new("alice", &password).unwrap())
                    .await,
                Err(CredentialError::Unavailable)
            ));
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        if config.starttls {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let rejecting = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = [0u8; 2];
                socket.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 0x30);
                assert!(header[1] < 128);
                let mut payload = vec![0u8; header[1] as usize];
                socket.read_exact(&mut payload).await.unwrap();
                let oid = b"1.3.6.1.4.1.1466.20037";
                assert!(
                    payload.windows(oid.len()).any(|window| window == oid),
                    "first operation was not StartTLS"
                );
                let mut message = [0u8; 4096];
                // LDAP ExtendedResponse: unavailable, empty matched DN and diagnostic.
                socket
                    .write_all(&[
                        0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x34, 0x04, 0x00,
                        0x04, 0x00,
                    ])
                    .await
                    .unwrap();
                let next = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut message))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(next, 0, "client sent data after StartTLS rejection");
            });
            let mut refused = config.clone();
            refused.endpoint = format!("ldap://{address}");
            let provider =
                LdapProvider::compile(ProviderId::new("rejecting-starttls"), refused, &env)
                    .unwrap();
            assert!(matches!(
                provider
                    .verify_password(PasswordInput::new("alice", &password).unwrap())
                    .await,
                Err(CredentialError::Unavailable)
            ));
            rejecting.await.unwrap();
        }
        let mut wrong_ca = config;
        wrong_ca.ca = std::env::var("OWNED_LDAP_WRONG_CA").unwrap().into();
        let untrusted =
            LdapProvider::compile(ProviderId::new("untrusted"), wrong_ca, &env).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                untrusted
                    .verify_password(PasswordInput::new("alice", &password).unwrap())
                    .await,
                Err(CredentialError::Unavailable)
            ));
        }
        assert_eq!(
            untrusted.circuit.state(),
            Some(crate::auth_gateway::breaker::State::Open)
        );
        assert!(untrusted.circuit.admit().is_none());
    }
    #[test]
    fn group_dns_normalize_to_stable_keys_and_readable_names() {
        let g = group_from_dn("CN=Eng Backend , OU=Groups,DC=Example,DC=Test", None).unwrap();
        assert_eq!(g.key, "cn=eng backend,ou=groups,dc=example,dc=test");
        assert_eq!(g.name, "Eng Backend");
        let g = group_from_dn(r"cn=a\,b,dc=x", Some("Named".into())).unwrap();
        assert_eq!(g.name, "Named");
        assert_eq!(group_from_dn(r"cn=a\,b,dc=x", None).unwrap().name, "a,b");
        assert!(group_from_dn("", None).is_none());
        assert!(group_from_dn("cn=\u{7}", None).is_none());
        assert!(group_from_dn(&format!("cn={}", "a".repeat(600)), None).is_none());
    }

    #[test]
    fn stored_subjects_become_escaped_lookup_filters() {
        assert_eq!(
            subject_filter("t:entryuuid:abc*)(x=1", "entryUUID", SubjectEncoding::Text).unwrap(),
            r"(entryUUID=abc\2a\29\28x=1)"
        );
        assert_eq!(
            subject_filter(
                "b:objectguid:0001ff",
                "objectGUID",
                SubjectEncoding::BinaryHex
            )
            .unwrap(),
            r"(objectGUID=\00\01\ff)"
        );
        assert!(subject_filter("t:uid:abc", "entryUUID", SubjectEncoding::Text).is_none());
        assert!(
            subject_filter("b:objectguid:0g", "objectGUID", SubjectEncoding::BinaryHex).is_none()
        );
        assert!(
            subject_filter("t:entryuuid:abc", "entryUUID", SubjectEncoding::BinaryHex).is_none()
        );
    }

    #[test]
    fn group_sync_settings_come_from_the_row_and_take_part_in_matching() {
        let row = serde_json::json!({"ldap": {}, "groups": {"max_groups": 5}});
        assert_eq!(
            ldap_groups_of(&row),
            Some(crate::groups::LdapGroups::default())
        );
        assert_eq!(ldap_groups_of(&serde_json::json!({"ldap": {}})), None);
        let row = serde_json::json!({"groups": {"ldap": {"mode": "search", "search_base_dn": "ou=g,dc=x"}}});
        let g = ldap_groups_of(&row).unwrap();
        assert_eq!(g.mode, crate::groups::LdapGroupMode::Search);
        assert_eq!(g.member_attribute, "member");
    }

    #[test]
    fn ldap_configuration_rejects_plaintext_and_filter_injection() {
        let mut config = Config {
            endpoint: "ldaps://directory.example.test/".into(),
            starttls: false,
            ca: "/owned/ca.pem".into(),
            base_dn: "dc=example,dc=test".into(),
            bind_dn: "cn=reader,dc=example,dc=test".into(),
            bind_password_env: "OWNED_LDAP_KEY".into(),
            username_attribute: "uid".into(),
            subject_attribute: "entryUUID".into(),
            subject_encoding: SubjectEncoding::Text,
            timeout_ms: 1000,
        };
        assert!(config.validate().is_ok());
        config.endpoint = "ldap://directory.example.test/".into();
        assert!(config.validate().is_err());
        config.starttls = true;
        assert!(config.validate().is_ok());
        config.username_attribute = "uid)(objectClass=*".into();
        assert!(config.validate().is_err());
        assert_eq!(
            ldap3::ldap_escape("worker*)(uid=*)").as_ref(),
            r"worker\2a\29\28uid=\2a\29"
        );
    }
}
