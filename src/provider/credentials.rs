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
#[cfg(test)]
mod tests {
    use super::*;
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
