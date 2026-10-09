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
    /// All ids, in `(sort_order, id)` order.
    order: Vec<ProviderId>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry {
            by_id: HashMap::new(),
            order: Vec::new(),
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
        let mut sorted: Vec<&ProviderRow> = rows.iter().collect();
        sorted.sort_by(|a, b| {
            (a.sort_order, a.provider_id.as_str()).cmp(&(b.sort_order, b.provider_id.as_str()))
        });
        let mut reg = Registry::empty();
        for row in sorted {
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
            } else {
                p.spawn_refresher();
            }
            reg.order.push(row.provider_id.clone());
            reg.by_id.insert(row.provider_id.clone(), p);
        }
        reg
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
/// row keeps what the configuration resolved.
pub fn apply_stored_reauth(
    providers: &mut [crate::policy::types::ProviderConfig],
    rows: &[ProviderRow],
) {
    for p in providers {
        if let Some(row) = rows.iter().find(|r| r.provider_id == p.provider_id) {
            (p.reauth, p.reauth_prompt) = crate::provider::oidc::reauth_settings(row);
        }
    }
}

impl crate::session::service::ProviderLookup for Registry {
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
        let mut providers = vec![cfg("a"), cfg("b"), cfg("rowless")];
        apply_stored_reauth(&mut providers, &[api, row("b", 1)]);
        assert_eq!(
            (providers[0].reauth, providers[0].reauth_prompt),
            (ReauthCapability::Unsupported, ReauthPrompt::None)
        );
        assert_eq!(providers[1].reauth, ReauthCapability::MaxAge);
        assert_eq!(providers[2].reauth, ReauthCapability::MaxAge);
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
