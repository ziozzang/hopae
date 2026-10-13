//! Session identifiers and the authentication facts a session carries.

use std::fmt;

use crate::crypto::Timestamp;
use crate::provider::types::ProviderId;

string_newtype!(
    /// Session identifier, `s_` + 26 Crockford base32 characters. Never the handle.
    SessionId
);
string_newtype!(
    /// Login transaction identifier (`t_...`); the bearer value is hashed, this is for logs.
    TransactionId
);

/// Authenticator assurance level (ADR-0008).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Aal {
    One = 1,
    Two = 2,
}

impl Aal {
    pub fn from_i64(n: i64) -> Option<Aal> {
        match n {
            1 => Some(Aal::One),
            2 => Some(Aal::Two),
            _ => None,
        }
    }

    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    Oidc,
    Oauth2,
    EmailLink,
    Password,
    Totp,
    External,
    Webauthn,
    Recovery,
}

impl FactorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FactorKind::Oidc => "oidc",
            FactorKind::Oauth2 => "oauth2",
            FactorKind::EmailLink => "email_link",
            FactorKind::Password => "password",
            FactorKind::Totp => "totp",
            FactorKind::External => "external",
            FactorKind::Webauthn => "webauthn",
            FactorKind::Recovery => "recovery",
        }
    }
}

/// One satisfied factor: stored in `sessions.factors` as `{kind, provider?, at}`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FactorEntry {
    pub kind: FactorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    pub at: Timestamp,
}

/// `x-hopae-gen` value `s<n>.u<n>.c<n>` (the epoch prefix is M2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Generations {
    pub session: u64,
    pub user: u64,
    pub config: u64,
}

impl fmt::Display for Generations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}.u{}.c{}", self.session, self.user, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_format_and_factor_json() {
        let g = Generations {
            session: 2,
            user: 3,
            config: 5,
        };
        assert_eq!(g.to_string(), "s2.u3.c5");
        let f = FactorEntry {
            kind: FactorKind::EmailLink,
            provider: None,
            at: Timestamp(9),
        };
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(j, r#"{"kind":"email_link","at":9}"#);
        assert_eq!(serde_json::from_str::<FactorEntry>(&j).unwrap(), f);
        assert!(Aal::One < Aal::Two);
        assert_eq!(Aal::from_i64(2), Some(Aal::Two));
        assert_eq!(Aal::from_i64(3), None);
    }
}
