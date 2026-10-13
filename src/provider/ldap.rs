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
pub struct LdapProvider {
    id: ProviderId,
    config: Config,
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
        Ok(Self {
            id,
            config,
            bind_password: Secret::new(password),
            tls: Arc::new(tls),
            capacity: tokio::sync::Semaphore::new(64),
            circuit: crate::auth_gateway::breaker::Circuit::new(3, 30_000)
                .expect("constant circuit bounds"),
        })
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
        let mut search = lookup
            .ldap
            .with_search_options(options)
            .streaming_search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                [self.config.subject_attribute.as_str()],
            )
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
            selected = Some((entry.dn, subject));
        }
        let result = search.finish().await;
        if result.rc != 0 || !result.refs.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        let (dn, subject) = selected.ok_or(CredentialError::Invalid)?;
        drop(search);
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
        })
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
