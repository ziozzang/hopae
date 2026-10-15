//! The set of configured providers, built from the `providers` rows. Rows
//! that are disabled or soft-deleted stay in the registry so a callback for
//! them is rejected with `provider_disabled` rather than "unknown provider";
//! only enabled ones appear in the chooser.

use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::Clock;
use crate::provider::oidc::{OidcProvider, Reporter};
use crate::provider::types::{Provider, ProviderId, ProviderKind};
use crate::store::types::ProviderRow;

pub struct Registry {
    by_id: HashMap<ProviderId, Arc<dyn Provider>>,
    credential_by_id: HashMap<ProviderId, Arc<dyn super::credentials::CredentialProvider>>,
    credential_order: Vec<ProviderId>,
    /// All ids, in `(sort_order, id)` order.
    order: Vec<ProviderId>,
    owners: Option<OwnedProviders>,
    deferred_refreshers: Vec<Arc<OidcProvider>>,
}
struct OwnedProviders {
    prepared: crate::store::sqlite::provider_owner::PreparedProviders,
    application: Arc<crate::policy::types::ConfigSnapshot>,
    applications: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
    published: std::sync::atomic::AtomicBool,
}
/// Infrastructure only: not a Human login, factor or observed clock capability.
#[allow(dead_code)]
pub(crate) struct RegistryProviderFence {
    registry: std::sync::Weak<Registry>,
    provider: ProviderId,
    retired: std::sync::atomic::AtomicBool,
}

struct DisabledCredentialProvider {
    id: ProviderId,
}
#[async_trait::async_trait]
impl super::credentials::CredentialProvider for DisabledCredentialProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn kind(&self) -> super::credentials::CredentialKind {
        super::credentials::CredentialKind::Ldap
    }
    fn enabled(&self) -> bool {
        false
    }
    async fn verify_password(
        &self,
        _: super::credentials::PasswordInput<'_>,
    ) -> Result<super::ProviderIdentity, super::credentials::CredentialError> {
        Err(super::credentials::CredentialError::Disabled)
    }
}
impl Registry {
    pub fn empty() -> Registry {
        Registry {
            by_id: HashMap::new(),
            credential_by_id: HashMap::new(),
            credential_order: Vec::new(),
            order: Vec::new(),
            owners: None,
            deferred_refreshers: Vec::new(),
        }
    }

    /// Build providers from rows. `env` resolves `client_secret_env` names;
    /// a missing variable disables that provider. With a Tokio runtime
    /// present, each OIDC provider starts its background refresher (discovery
    /// is fetched immediately, so `health()` turns `Ok` without a login).
    pub fn from_snapshot(
        rows: &[ProviderRow],
        env: &dyn Fn(&str) -> Option<String>,
        clock: Arc<dyn Clock>,
        reporter: Option<Reporter>,
    ) -> Registry {
        Self::compile(rows, env, clock, reporter, true)
    }

    fn compile(
        rows: &[ProviderRow],
        env: &dyn Fn(&str) -> Option<String>,
        clock: Arc<dyn Clock>,
        reporter: Option<Reporter>,
        start_refreshers: bool,
    ) -> Registry {
        let mut sorted: Vec<&ProviderRow> = rows.iter().collect();
        sorted.sort_by(|a, b| {
            (a.sort_order, a.provider_id.as_str()).cmp(&(b.sort_order, b.provider_id.as_str()))
        });
        let mut reg = Registry::empty();
        for row in sorted {
            if reg.by_id.contains_key(&row.provider_id)
                || reg.credential_by_id.contains_key(&row.provider_id)
            {
                continue;
            }
            if row.kind == ProviderKind::Ldap {
                let provider = if row.enabled && row.deleted_at.is_none() {
                    row.config
                        .get("ldap")
                        .cloned()
                        .and_then(|value| serde_json::from_value::<super::ldap::Config>(value).ok())
                        .and_then(|config| {
                            super::ldap::LdapProvider::compile(row.provider_id.clone(), config, env)
                                .ok()
                        })
                } else {
                    None
                };
                let provider: Arc<dyn super::credentials::CredentialProvider> = match provider {
                    Some(provider) => Arc::new(provider),
                    None => Arc::new(DisabledCredentialProvider {
                        id: row.provider_id.clone(),
                    }),
                };
                reg.credential_order.push(row.provider_id.clone());
                reg.credential_by_id
                    .insert(row.provider_id.clone(), provider);
                continue;
            }
            if row.kind != ProviderKind::Oidc {
                tracing::warn!(provider = %row.provider_id, kind = row.kind.as_str(), "provider kind not supported yet; skipped");
                continue;
            }
            if reg.by_id.contains_key(&row.provider_id) {
                continue;
            }
            let p = OidcProvider::from_row(row, env, clock.clone(), reporter.clone());
            if let Some(why) = p.disabled_reason() {
                tracing::warn!(provider = %row.provider_id, reason = why, "provider is not usable");
            } else if start_refreshers {
                p.spawn_refresher();
            } else {
                reg.deferred_refreshers.push(p.clone());
            }
            reg.order.push(row.provider_id.clone());
            reg.by_id.insert(row.provider_id.clone(), p);
        }
        reg
    }

    pub(crate) fn from_prepared(
        prepared: crate::store::sqlite::provider_owner::PreparedProviders,
        applications: Arc<arc_swap::ArcSwap<crate::policy::types::ConfigSnapshot>>,
        env: &dyn Fn(&str) -> Option<String>,
        clock: Arc<dyn Clock>,
        reporter: Option<Reporter>,
    ) -> crate::store::StoreResult<Self> {
        let application = applications.load_full();
        if application.generation != prepared.generation() {
            return Err(crate::store::StoreError::Conflict(
                "provider application owner changed",
            ));
        }
        let mut registry = Self::compile(prepared.rows(), env, clock, reporter, false);
        registry.owners = Some(OwnedProviders {
            prepared,
            application,
            applications,
            published: std::sync::atomic::AtomicBool::new(false),
        });
        Ok(registry)
    }
    fn owners(&self) -> crate::store::StoreResult<&OwnedProviders> {
        let owners = self
            .owners
            .as_ref()
            .ok_or(crate::store::StoreError::Conflict(
                "provider registry unqualified",
            ))?;
        if !Arc::ptr_eq(&owners.application, &owners.applications.load_full()) {
            return Err(crate::store::StoreError::Conflict(
                "provider application owner changed",
            ));
        }
        Ok(owners)
    }
    /// Called after fallible bind/listener preparation. A failed publication
    /// starts no refresher tasks; later run/router failures retain the existing
    /// Weak refresher lifecycle, including a bounded in-flight request.
    pub(crate) async fn publish_prepared(
        &self,
        store: &crate::store::Store,
        deadline: crate::store::Deadline,
    ) -> crate::store::StoreResult<()> {
        let owners = self.owners()?;
        store
            .require_prepared_providers(&owners.prepared, deadline)
            .await?;
        self.owners()?;
        if !owners
            .published
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            for provider in &self.deferred_refreshers {
                provider.spawn_refresher();
            }
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) async fn capture_provider_fence(
        self: &Arc<Self>,
        store: &crate::store::Store,
        id: &ProviderId,
        deadline: crate::store::Deadline,
    ) -> crate::store::StoreResult<RegistryProviderFence> {
        let fence = RegistryProviderFence {
            registry: Arc::downgrade(self),
            provider: id.clone(),
            retired: std::sync::atomic::AtomicBool::new(false),
        };
        self.require_provider_fence(store, &fence, deadline).await?;
        Ok(fence)
    }
    #[allow(dead_code)]
    pub(crate) async fn require_provider_fence(
        self: &Arc<Self>,
        store: &crate::store::Store,
        fence: &RegistryProviderFence,
        deadline: crate::store::Deadline,
    ) -> crate::store::StoreResult<()> {
        let result = async {
            if fence.retired.load(std::sync::atomic::Ordering::Acquire)
                || !std::sync::Weak::ptr_eq(&fence.registry, &Arc::downgrade(self))
            {
                return Err(crate::store::StoreError::Conflict(
                    "provider registry fence retired",
                ));
            }
            let owners = self.owners()?;
            let usable = self
                .credential(&fence.provider)
                .is_some_and(|p| p.enabled())
                || self.get(&fence.provider).is_some_and(|p| p.enabled());
            if !owners.published.load(std::sync::atomic::Ordering::Acquire) || !usable {
                return Err(crate::store::StoreError::Conflict(
                    "compiled provider unavailable",
                ));
            }
            store
                .require_prepared_provider(&owners.prepared, &fence.provider, deadline)
                .await?;
            self.owners()?;
            // Observe concurrent retirement after the durable read. This is a
            // point-in-time fence check, not an atomic remote authorization.
            if fence.retired.load(std::sync::atomic::Ordering::Acquire) {
                return Err(crate::store::StoreError::Conflict(
                    "provider registry fence retired",
                ));
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            fence
                .retired
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    pub fn credential(
        &self,
        id: &ProviderId,
    ) -> Option<Arc<dyn super::credentials::CredentialProvider>> {
        self.credential_by_id.get(id).cloned()
    }
    pub fn enabled_credentials(&self) -> Vec<Arc<dyn super::credentials::CredentialProvider>> {
        self.credential_order
            .iter()
            .filter_map(|id| self.credential_by_id.get(id))
            .filter(|provider| provider.enabled())
            .cloned()
            .collect()
    }
    /// Any configured provider, including disabled ones.
    pub fn get(&self, id: &ProviderId) -> Option<Arc<dyn Provider>> {
        self.by_id.get(id).cloned()
    }

    /// Enabled providers in chooser order.
    pub fn enabled_sorted(&self) -> Vec<Arc<dyn Provider>> {
        self.order
            .iter()
            .filter_map(|id| self.by_id.get(id))
            .filter(|p| p.enabled())
            .cloned()
            .collect()
    }

    /// Every provider in chooser order (for `/healthz`).
    pub fn all_sorted(&self) -> Vec<Arc<dyn Provider>> {
        self.order
            .iter()
            .filter_map(|id| self.by_id.get(id))
            .cloned()
            .collect()
    }
}

/// Make a snapshot's provider capabilities agree with the stored rows: a
/// stored `reauth` / `reauth_prompt` setting (an api-managed row's override)
/// beats the file's preset default (ADR-0016 decision 15). A provider with no
/// row keeps what the configuration resolved; a retained database provider
/// the file no longer lists gets its stored capability recorded in
/// `retained_reauth`, so [`ConfigSnapshot::reauth_capability`] answers for it.
pub fn apply_stored_reauth(
    snapshot: &mut crate::policy::types::ConfigSnapshot,
    rows: &[ProviderRow],
) {
    for p in &mut snapshot.providers {
        if let Some(row) = rows.iter().find(|r| r.provider_id == p.provider_id) {
            (p.reauth, p.reauth_prompt) = crate::provider::oidc::reauth_settings(row);
        }
    }
    for row in rows {
        if !snapshot
            .providers
            .iter()
            .any(|p| p.provider_id == row.provider_id)
        {
            snapshot.retained_reauth.insert(
                row.provider_id.clone(),
                crate::provider::oidc::reauth_settings(row).0,
            );
        }
    }
}

impl crate::session::service::ProviderLookup for Registry {
    fn credential(
        &self,
        id: &ProviderId,
    ) -> Option<Arc<dyn super::credentials::CredentialProvider>> {
        Registry::credential(self, id)
    }
    fn enabled_credentials(&self) -> Vec<Arc<dyn super::credentials::CredentialProvider>> {
        Registry::enabled_credentials(self)
    }
    fn get(&self, id: &ProviderId) -> Option<Arc<dyn Provider>> {
        Registry::get(self, id)
    }

    fn enabled_sorted(&self) -> Vec<Arc<dyn Provider>> {
        Registry::enabled_sorted(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{TestClock, Timestamp};
    use crate::store::types::ManagedBy;

    fn row(id: &str, sort: i32) -> ProviderRow {
        ProviderRow {
            provider_id: ProviderId::new(id),
            kind: ProviderKind::Oidc,
            display_name: id.to_string(),
            enabled: true,
            managed_by: ManagedBy::File,
            deleted_at: None,
            sort_order: sort,
            config: serde_json::json!({"client_id": "c", "issuer": "https://idp.example.test"}),
            client_secret_env: Some("SECRET_ENV".into()),
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
        }
    }

    fn clock() -> Arc<dyn Clock> {
        Arc::new(TestClock::new(Timestamp(1_800_000_000_000)))
    }

    #[test]
    fn disabled_or_invalid_directory_rows_remain_addressable_without_redirect_registration() {
        let mut disabled = row("disabled-directory", 0);
        disabled.kind = ProviderKind::Ldap;
        disabled.enabled = false;
        let mut deleted = row("deleted-directory", 1);
        deleted.kind = ProviderKind::Ldap;
        deleted.deleted_at = Some(Timestamp(1));
        let registry = Registry::from_snapshot(
            &[disabled, deleted],
            &|_| panic!("disabled directory must not read credentials"),
            clock(),
            None,
        );
        for id in ["disabled-directory", "deleted-directory"] {
            let id = ProviderId::new(id);
            assert!(!registry.credential(&id).unwrap().enabled());
            assert!(registry.get(&id).is_none());
        }
        assert!(registry.enabled_credentials().is_empty());
        let mut named_preset = row("google", 0);
        named_preset.kind = ProviderKind::Ldap;
        named_preset.config = serde_json::json!({"reauth":"max_age"});
        assert_eq!(
            crate::provider::oidc::reauth_settings(&named_preset),
            (
                crate::provider::ReauthCapability::Unsupported,
                crate::provider::ReauthPrompt::None
            )
        );
        let mut invalid = row("invalid-directory", 0);
        invalid.kind = ProviderKind::Ldap;
        let registry = Registry::from_snapshot(&[invalid], &|_| None, clock(), None);
        assert!(
            !registry
                .credential(&ProviderId::new("invalid-directory"))
                .unwrap()
                .enabled()
        );
    }
    #[test]
    fn ordering_visibility_and_tombstones() {
        let mut gone = row("gone", 1);
        gone.deleted_at = Some(Timestamp(5));
        let mut off = row("off", 2);
        off.enabled = false;
        let mut nosecret = row("nosecret", 3);
        nosecret.client_secret_env = Some("MISSING".into());
        let rows = vec![
            row("zeta", 0),
            row("alpha", 0),
            gone,
            off,
            nosecret,
            row("a", 9),
        ];
        let env = |n: &str| (n == "SECRET_ENV").then(|| "v".to_string());
        let reg = Registry::from_snapshot(&rows, &env, clock(), None);

        let ids = |v: Vec<Arc<dyn Provider>>| -> Vec<String> {
            v.iter().map(|p| p.id().to_string()).collect()
        };
        assert_eq!(ids(reg.enabled_sorted()), ["alpha", "zeta", "a"]);
        assert_eq!(
            ids(reg.all_sorted()),
            ["alpha", "zeta", "gone", "off", "nosecret", "a"]
        );
        // Disabled, deleted and secret-less providers are still found, so a
        // callback for them is rejected as disabled, not as unknown.
        for id in ["gone", "off", "nosecret"] {
            let p = reg.get(&ProviderId::new(id)).expect(id);
            assert!(!p.enabled(), "{id}");
        }
        assert!(reg.get(&ProviderId::new("nope")).is_none());
    }

    #[test]
    fn stored_reauth_settings_update_the_snapshot() {
        use crate::policy::types::ProviderConfig;
        use crate::provider::types::{ReauthCapability, ReauthPrompt};
        let cfg = |id: &str| ProviderConfig {
            provider_id: ProviderId::new(id),
            kind: ProviderKind::Oidc,
            display_name: id.into(),
            enabled: true,
            client_id: "c".into(),
            ldap: None,
            client_secret_env: None,
            issuer: None,
            scope: String::new(),
            endpoint_hosts: vec![],
            allow_private_endpoints: None,
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
            sort_order: 0,
            reauth: ReauthCapability::MaxAge,
            reauth_prompt: ReauthPrompt::Login,
        };
        let mut api = row("a", 0);
        api.config = serde_json::json!({"client_id": "c", "issuer": "https://i.example.test", "reauth": "unsupported", "reauth_prompt": "none"});
        let mut kept = row("kept", 2);
        kept.config = serde_json::json!({"client_id": "c", "issuer": "https://i.example.test", "reauth": "unsupported"});
        let mut snap = crate::policy::types::ConfigSnapshot {
            generation: 0,
            apps: vec![],
            default_app: crate::policy::types::AppPolicy::default_app(),
            providers: vec![cfg("a"), cfg("b"), cfg("rowless")],
            retained_reauth: Default::default(),
        };
        apply_stored_reauth(&mut snap, &[api, row("b", 1), kept]);
        let p = &snap.providers;
        assert_eq!(
            (p[0].reauth, p[0].reauth_prompt),
            (ReauthCapability::Unsupported, ReauthPrompt::None)
        );
        assert_eq!(p[1].reauth, ReauthCapability::MaxAge);
        assert_eq!(p[2].reauth, ReauthCapability::MaxAge);
        // A retained database provider absent from the file keeps its stored
        // capability; an unknown id gets the default.
        assert_eq!(
            snap.reauth_capability(&ProviderId::new("kept")),
            ReauthCapability::Unsupported
        );
        assert_eq!(
            snap.reauth_capability(&ProviderId::new("a")),
            ReauthCapability::Unsupported
        );
        assert_eq!(
            snap.reauth_capability(&ProviderId::new("nobody")),
            ReauthCapability::MaxAge
        );
    }

    #[test]
    fn unsupported_kinds_and_duplicates_are_skipped() {
        let mut pw = row("pw", 0);
        pw.kind = ProviderKind::Password;
        let rows = vec![pw, row("a", 1), row("a", 2)];
        let env = |_: &str| Some("v".to_string());
        let reg = Registry::from_snapshot(&rows, &env, clock(), None);
        assert_eq!(reg.all_sorted().len(), 1);
        assert!(reg.get(&ProviderId::new("pw")).is_none());
    }
}

#[cfg(test)]
#[path = "registry_owner_tests.rs"]
mod owner_tests;
