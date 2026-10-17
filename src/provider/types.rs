//! The provider abstraction (ADR-0010): identifiers, results, errors and the trait.

use async_trait::async_trait;

use crate::crypto::{Rng, Secret};
use crate::event::types::{Reason, reasons};
use crate::identity::types::NormalizedEmail;
use crate::store::types::TransactionRow;

string_newtype!(
    /// Provider identifier from the configuration (`google`, `mock`, ...).
    ProviderId
);

/// The reserved provider id of a passwordless passkey session (ADR-0017
/// decision 16). Never a configured provider: a provider id is a slug
/// (`[a-z0-9][a-z0-9_-]*`) and cannot contain the `.`, and no `providers` row names it. Such a session stays live
/// while the passkey it was established with is active.
pub const PASSKEY_PROVIDER: &str = "hopae.passkey";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Oidc,
    Oauth2,
    EmailLink,
    Password,
    Ldap,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Oidc => "oidc",
            ProviderKind::Oauth2 => "oauth2",
            ProviderKind::EmailLink => "email_link",
            ProviderKind::Password => "password",
            ProviderKind::Ldap => "ldap",
        }
    }

    pub fn parse(s: &str) -> Option<ProviderKind> {
        match s {
            "oidc" => Some(ProviderKind::Oidc),
            "oauth2" => Some(ProviderKind::Oauth2),
            "email_link" => Some(ProviderKind::EmailLink),
            "password" => Some(ProviderKind::Password),
            "ldap" => Some(ProviderKind::Ldap),
            _ => None,
        }
    }
}

/// Whether a provider honors the OpenID Connect `max_age` parameter and
/// returns `auth_time`, so a console reauthentication is a provider-verified
/// challenge (ADR-0016 decision 15). Stored provider setting `reauth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReauthCapability {
    MaxAge,
    Unsupported,
}

impl ReauthCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthCapability::MaxAge => "max_age",
            ReauthCapability::Unsupported => "unsupported",
        }
    }

    pub fn parse(s: &str) -> Option<ReauthCapability> {
        match s {
            "max_age" => Some(ReauthCapability::MaxAge),
            "unsupported" => Some(ReauthCapability::Unsupported),
            _ => None,
        }
    }
}

/// Whether a reauthentication authorize request to a `max_age` provider also
/// carries `prompt=login`. Stored provider setting `reauth_prompt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReauthPrompt {
    Login,
    None,
}

impl ReauthPrompt {
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthPrompt::Login => "login",
            ReauthPrompt::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<ReauthPrompt> {
        match s {
            "login" => Some(ReauthPrompt::Login),
            "none" => Some(ReauthPrompt::None),
            _ => None,
        }
    }
}

pub struct AuthorizationRequest {
    pub url: url::Url,
    pub state: Secret,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<Secret>,
}

pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// One group a provider asserted, before the provider's mapping rules: a
/// stable source key (an LDAP DN, an OIDC claim value) and a display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawGroup {
    pub key: String,
    pub name: String,
}

pub struct ProviderIdentity {
    pub subject: String,
    pub email: Option<NormalizedEmail>,
    pub email_verified: bool,
    pub email_authoritative: bool,
    pub name: Option<String>,
    pub username: Option<String>,
    pub picture: Option<String>,
    /// At most 8 KiB serialized.
    pub raw_claims: serde_json::Value,
    /// The ID token's `auth_time` claim, raw (any JSON): `freshness::validate_claim`
    /// is the only place it is interpreted (ADR-0016).
    pub auth_time: Option<serde_json::Value>,
    /// The person's complete group set as the provider asserted it, when the
    /// provider syncs groups and the assertion carried them; `None` means
    /// "not asserted" (existing memberships are left as they are).
    pub groups: Option<Vec<RawGroup>>,
}

/// A reauthentication request the portal passes to `Provider::begin` only for
/// a provider whose capability is `max_age`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReauthRequest {
    pub max_age: std::time::Duration,
}

/// Each variant maps to one reason code (see [`ProviderError::reason`]).
#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("invalid_credentials")]
    InvalidCredentials,
    #[error("invalid_state")]
    InvalidState,
    #[error("invalid_nonce")]
    InvalidNonce,
    #[error("invalid_audience")]
    InvalidAudience,
    #[error("invalid_issuer")]
    InvalidIssuer,
    #[error("invalid_signature")]
    InvalidSignature,
    #[error("invalid_token_header")]
    InvalidTokenHeader,
    #[error("token_expired")]
    TokenExpired,
    #[error("id_token_missing")]
    IdTokenMissing,
    #[error("userinfo_subject_mismatch")]
    UserinfoSubjectMismatch,
    #[error("provider_error (status {status})")]
    ProviderError { status: u16 },
    #[error("provider_timeout")]
    ProviderTimeout,
    #[error("provider_response_invalid")]
    ProviderResponseInvalid,
    #[error("provider_response_too_large")]
    ProviderResponseTooLarge,
    #[error("provider_unavailable")]
    ProviderUnavailable,
    #[error("provider_disabled")]
    ProviderDisabled,
    #[error("discovery_issuer_mismatch")]
    DiscoveryIssuerMismatch,
}

impl ProviderError {
    /// The stable reason code for events and failure pages.
    pub fn reason(&self) -> Reason {
        match self {
            ProviderError::InvalidCredentials => reasons::INVALID_CREDENTIALS,
            ProviderError::InvalidState => reasons::INVALID_STATE,
            ProviderError::InvalidNonce => reasons::INVALID_NONCE,
            ProviderError::InvalidAudience => reasons::INVALID_AUDIENCE,
            ProviderError::InvalidIssuer => reasons::INVALID_ISSUER,
            ProviderError::InvalidSignature => reasons::INVALID_SIGNATURE,
            ProviderError::InvalidTokenHeader => reasons::INVALID_TOKEN_HEADER,
            ProviderError::TokenExpired => reasons::TOKEN_EXPIRED,
            ProviderError::IdTokenMissing => reasons::ID_TOKEN_MISSING,
            ProviderError::UserinfoSubjectMismatch => reasons::USERINFO_SUBJECT_MISMATCH,
            ProviderError::ProviderError { .. } => reasons::PROVIDER_ERROR,
            ProviderError::ProviderTimeout => reasons::PROVIDER_TIMEOUT,
            ProviderError::ProviderResponseInvalid => reasons::PROVIDER_RESPONSE_INVALID,
            ProviderError::ProviderResponseTooLarge => reasons::PROVIDER_RESPONSE_TOO_LARGE,
            ProviderError::ProviderUnavailable => reasons::PROVIDER_UNAVAILABLE,
            ProviderError::ProviderDisabled => reasons::PROVIDER_DISABLED,
            ProviderError::DiscoveryIssuerMismatch => reasons::DISCOVERY_ISSUER_MISMATCH,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderHealth {
    Ok,
    Degraded(&'static str),
    Disabled,
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn kind(&self) -> ProviderKind;
    fn display_name(&self) -> &str;
    fn enabled(&self) -> bool;
    async fn begin(
        &self,
        txn: &TransactionRow,
        redirect_uri: &url::Url,
        rng: &dyn Rng,
    ) -> Result<AuthorizationRequest, ProviderError>;
    /// As [`Provider::begin`], carrying a reauthentication request the portal
    /// passes only for a `max_age` provider (ADR-0016). A provider with no
    /// notion of it ignores the request.
    async fn begin_reauth(
        &self,
        txn: &TransactionRow,
        redirect_uri: &url::Url,
        rng: &dyn Rng,
        reauth: Option<ReauthRequest>,
    ) -> Result<AuthorizationRequest, ProviderError> {
        let _ = reauth;
        self.begin(txn, redirect_uri, rng).await
    }
    async fn complete(
        &self,
        txn: &TransactionRow,
        callback: &CallbackQuery,
        redirect_uri: &url::Url,
    ) -> Result<ProviderIdentity, ProviderError>;
    async fn health(&self) -> ProviderHealth;
    /// Health after giving a provider that has not completed discovery yet a
    /// short, bounded chance to (a visitor must not see "temporarily
    /// unavailable" for the first milliseconds after start). The default is
    /// just [`Provider::health`].
    async fn ensure_ready(&self) -> ProviderHealth {
        self.health().await
    }
    /// Origin of the authorization endpoint from the discovery already held
    /// (never fetched here), for the portal's per-page CSP `form-action`.
    /// The outbound TLS trust of the provider (OIDC: its CA source and client
    /// certificate), for the admin status. `None` for kinds without one.
    fn tls_status(&self) -> Option<serde_json::Value> {
        None
    }
    fn authorization_origin(&self) -> Option<url::Origin> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_reason_matches_its_display_code() {
        let all = [
            ProviderError::InvalidCredentials,
            ProviderError::InvalidState,
            ProviderError::InvalidNonce,
            ProviderError::InvalidAudience,
            ProviderError::InvalidIssuer,
            ProviderError::InvalidSignature,
            ProviderError::InvalidTokenHeader,
            ProviderError::TokenExpired,
            ProviderError::IdTokenMissing,
            ProviderError::UserinfoSubjectMismatch,
            ProviderError::ProviderTimeout,
            ProviderError::ProviderResponseInvalid,
            ProviderError::ProviderResponseTooLarge,
            ProviderError::ProviderUnavailable,
            ProviderError::ProviderDisabled,
            ProviderError::DiscoveryIssuerMismatch,
        ];
        for e in all {
            assert_eq!(e.reason().0, e.to_string());
        }
        let e = ProviderError::ProviderError { status: 500 };
        assert_eq!(e.reason().0, "provider_error");
    }

    #[test]
    fn kind_round_trips() {
        for k in [
            ProviderKind::Oidc,
            ProviderKind::Oauth2,
            ProviderKind::EmailLink,
            ProviderKind::Password,
            ProviderKind::Ldap,
        ] {
            assert_eq!(ProviderKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(ProviderKind::parse("saml"), None);
    }
}
