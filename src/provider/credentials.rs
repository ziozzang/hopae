//! Direct password providers share identity/session handling with redirect providers.
//! Portal transaction, browser binding, CSRF and throttling must precede this interface.
use super::{ProviderId, ProviderIdentity};
use crate::crypto::Secret;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    Ldap,
    LocalPassword,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid_credentials")]
    Invalid,
    #[error("credential_provider_unavailable")]
    Unavailable,
    #[error("credential_provider_disabled")]
    Disabled,
}
/// Borrowed only for the bounded verification operation. No serialization or cloning.
pub struct PasswordInput<'a> {
    username: &'a str,
    password: &'a Secret,
}
impl<'a> PasswordInput<'a> {
    pub fn new(username: &'a str, password: &'a Secret) -> Result<Self, CredentialError> {
        if username.is_empty()
            || username.len() > 256
            || username.chars().any(char::is_control)
            || password.expose().is_empty()
            || password.expose().len() > 4096
        {
            return Err(CredentialError::Invalid);
        }
        Ok(Self { username, password })
    }
    pub fn username(&self) -> &str {
        self.username
    }
    /// Trusted connector access only; never copy into diagnostics, headers or events.
    pub fn password(&self) -> &Secret {
        self.password
    }
}
impl std::fmt::Debug for PasswordInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PasswordInput([REDACTED])")
    }
}
/// Distinct from OAuth begin/callback: successful credential verification returns
/// the existing provider identity for ordinary Hopae identity/session processing.
/// A result is Human/AAL 1 with local authentication time; no provider auth_time/MFA
/// may be inferred. Implementations must return stable namespace subjects, avoid
/// implicit email linking, and distinguish outages from credential rejection.
#[async_trait::async_trait]
pub trait CredentialProvider: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn kind(&self) -> CredentialKind;
    fn enabled(&self) -> bool;
    async fn verify_password(
        &self,
        input: PasswordInput<'_>,
    ) -> Result<ProviderIdentity, CredentialError>;
}
/// Verified direct authentication; assurance and freshness provenance are fixed.
pub struct PasswordAuthentication {
    provider: ProviderId,
    identity: ProviderIdentity,
    authenticated_at: crate::crypto::Timestamp,
}
impl PasswordAuthentication {
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }
    pub fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }
    pub fn authenticated_at(&self) -> crate::crypto::Timestamp {
        self.authenticated_at
    }
    pub fn principal_kind(&self) -> crate::auth_gateway::PrincipalKind {
        crate::auth_gateway::PrincipalKind::Human
    }
    pub fn aal(&self) -> crate::session::types::Aal {
        crate::session::types::Aal::One
    }
    pub fn auth_time_source(&self) -> crate::store::types::AuthTimeSource {
        crate::store::types::AuthTimeSource::HopaeCompletion
    }
}
/// Must be called after portal transaction, binding, CSRF and throttling validation.
pub async fn authenticate_password(
    provider: &dyn CredentialProvider,
    input: PasswordInput<'_>,
    clock: &dyn crate::crypto::Clock,
) -> Result<PasswordAuthentication, CredentialError> {
    if !provider.enabled() {
        return Err(CredentialError::Disabled);
    }
    let id = provider.id().clone();
    let kind = provider.kind();
    let identity = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        provider.verify_password(input),
    )
    .await
    .map_err(|_| CredentialError::Unavailable)??;
    if !provider.enabled() {
        return Err(CredentialError::Disabled);
    }
    if provider.id() != &id
        || provider.kind() != kind
        || identity.auth_time.is_some()
        || identity.subject.is_empty()
        || identity.subject.len() > 256
        || identity.subject.chars().any(char::is_control)
        || identity.email_verified
        || identity.email_authoritative
        || identity
            .raw_claims
            .as_object()
            .is_none_or(|claims| !claims.is_empty())
    {
        return Err(CredentialError::Unavailable);
    }
    let authenticated_at = clock.now();
    if authenticated_at.0 < 0 {
        return Err(CredentialError::Unavailable);
    }
    Ok(PasswordAuthentication {
        provider: id,
        identity,
        authenticated_at,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    struct OwnedProvider {
        id: ProviderId,
        claim: bool,
        raw_claims: serde_json::Value,
        disable: bool,
        enabled: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl CredentialProvider for OwnedProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::Ldap
        }
        fn enabled(&self) -> bool {
            self.enabled.load(std::sync::atomic::Ordering::SeqCst)
        }
        async fn verify_password(
            &self,
            _: PasswordInput<'_>,
        ) -> Result<ProviderIdentity, CredentialError> {
            if self.disable {
                self.enabled
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(ProviderIdentity {
                subject: "t:entryuuid:owned".into(),
                email: None,
                email_verified: false,
                email_authoritative: false,
                name: None,
                username: None,
                picture: None,
                raw_claims: self.raw_claims.clone(),
                auth_time: self.claim.then(|| serde_json::json!(9999)),
            })
        }
    }
    #[tokio::test]
    async fn direct_result_has_local_aal_one_and_rejects_provider_time_or_late_disable() {
        let password = Secret::new("owned-credential".into());
        let clock = crate::crypto::TestClock::new(crate::crypto::Timestamp(1234));
        for (claim, disable) in [(false, false), (true, false), (false, true)] {
            let provider = OwnedProvider {
                id: ProviderId::new("owned"),
                claim,
                raw_claims: serde_json::json!({}),
                disable,
                enabled: std::sync::atomic::AtomicBool::new(true),
            };
            let result = authenticate_password(
                &provider,
                PasswordInput::new("worker", &password).unwrap(),
                &clock,
            )
            .await;
            if claim {
                assert!(matches!(result, Err(CredentialError::Unavailable)));
            } else if disable {
                assert!(matches!(result, Err(CredentialError::Disabled)));
            } else {
                let result = result.unwrap();
                assert_eq!(result.provider().as_str(), "owned");
                assert_eq!(result.authenticated_at().0, 1234);
                assert_eq!(result.aal(), crate::session::types::Aal::One);
                assert_eq!(
                    result.auth_time_source(),
                    crate::store::types::AuthTimeSource::HopaeCompletion
                );
            }
        }
    }
    #[tokio::test]
    async fn direct_authentication_rejects_unstructured_or_privilege_bearing_claims() {
        let password = Secret::new("owned-private-value".into());
        let clock = crate::crypto::TestClock::new(crate::crypto::Timestamp(1000));
        let mut echoed = serde_json::Map::new();
        echoed.insert("credential".into(), serde_json::json!(password.expose()));
        for raw_claims in [
            serde_json::json!({"aal":3}),
            serde_json::Value::Object(echoed),
            serde_json::Value::Null,
            serde_json::json!([]),
        ] {
            let provider = OwnedProvider {
                id: ProviderId::new("owned"),
                claim: false,
                raw_claims,
                disable: false,
                enabled: std::sync::atomic::AtomicBool::new(true),
            };
            assert!(matches!(
                authenticate_password(
                    &provider,
                    PasswordInput::new("worker", &password).unwrap(),
                    &clock
                )
                .await,
                Err(CredentialError::Unavailable)
            ));
        }
    }
    #[test]
    fn password_input_rejects_anonymous_bind_and_excessive_inputs_without_disclosure() {
        let empty = Secret::new(String::new());
        assert!(matches!(
            PasswordInput::new("worker", &empty),
            Err(CredentialError::Invalid)
        ));
        let password = Secret::new("owned-sensitive-password".into());
        for username in ["", "worker\0other", "worker\nother"] {
            assert!(matches!(
                PasswordInput::new(username, &password),
                Err(CredentialError::Invalid)
            ));
        }
        assert!(PasswordInput::new(&"a".repeat(257), &password).is_err());
        assert!(PasswordInput::new("worker", &Secret::new("x".repeat(4097))).is_err());
        let input = PasswordInput::new("owned-sensitive-username", &password).unwrap();
        assert_eq!(format!("{input:?}"), "PasswordInput([REDACTED])");
        // Whitespace is valid password material; never trim or normalize passwords.
        let spaces = Secret::new("  ".into());
        assert_eq!(
            PasswordInput::new("worker", &spaces)
                .unwrap()
                .password()
                .expose(),
            "  "
        );
    }
}
