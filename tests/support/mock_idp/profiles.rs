//! Mock identity provider profiles: data, not code paths. `default` is a
//! standard OIDC provider; every other profile changes exactly one thing, as
//! listed in the fixture catalogue of `scenarios/README.md`. One enum, one
//! `match`.
#![allow(dead_code)]

use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Default,
    WrongState,
    WrongNonce,
    ExpiredToken,
    WrongAud,
    InvalidSignature,
    UnverifiedEmail,
    UserinfoWrongSub,
    HdExampleTest,
    Oversized,
    Slow,
    DiscoveryDown,
    DiscoveryChangedIssuer,
    JwksRotated,
    JwksUnknownKid,
    Token500,
    TokenSlow,
    TokenMalformed,
    Userinfo500,
    IdTokenMissing,
    /// `auth_time` is the code issue time (a `max_age` provider).
    AuthTimePresent,
    /// `auth_time` is two days old.
    AuthTimeStale,
    /// The ID token carries no `auth_time` claim.
    AuthTimeMissing,
}

/// What the ID token's `auth_time` claim holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthTime {
    /// The time the code was issued (the provider's own clock).
    IssueTime,
    /// This many seconds before the code was issued.
    Stale(i64),
    /// No claim.
    Missing,
}

/// What a profile changes. `Behavior::standard()` is the `default` profile.
#[derive(Clone, Debug)]
pub struct Behavior {
    /// The callback redirect carries a `state` that was never issued.
    pub wrong_state: bool,
    /// The ID token `nonce` differs from the request's.
    pub wrong_nonce: bool,
    /// ID token lifetime relative to now: `exp = now + exp_offset`, `iat` 300 s before `exp`.
    pub exp_offset_secs: i64,
    /// The ID token `aud` is another client id.
    pub wrong_aud: bool,
    /// The ID token is signed by a key that is not in the JWKS (same `kid` as the real key).
    pub rogue_signature: bool,
    pub email_verified: bool,
    /// User-info answers with this subject (and that subject's email).
    pub userinfo_sub: Option<&'static str>,
    /// ID token carries `hd`.
    pub hd: Option<&'static str>,
    /// Discovery, JWKS and token responses are 1 MiB.
    pub oversized: bool,
    /// Every endpoint delays this long.
    pub delay_all: Option<Duration>,
    pub discovery_status: u16,
    /// Discovery `issuer` differs from the configured one after the first fetch.
    pub discovery_changes_issuer: bool,
    /// A new `kid` replaces the old one after the first JWKS fetch.
    pub jwks_rotates: bool,
    /// ID token `kid` never appears in the JWKS.
    pub unknown_kid: bool,
    pub token_status: Option<u16>,
    pub token_delay: Option<Duration>,
    /// Invalid JSON, then a numeric `id_token`, then invalid base64 (cycling).
    pub token_malformed: bool,
    pub userinfo_status: Option<u16>,
    pub omit_id_token: bool,
    pub auth_time: AuthTime,
}

impl Behavior {
    pub fn standard() -> Self {
        Behavior {
            wrong_state: false,
            wrong_nonce: false,
            exp_offset_secs: 300,
            wrong_aud: false,
            rogue_signature: false,
            email_verified: true,
            userinfo_sub: None,
            hd: None,
            oversized: false,
            delay_all: None,
            discovery_status: 200,
            discovery_changes_issuer: false,
            jwks_rotates: false,
            unknown_kid: false,
            token_status: None,
            token_delay: None,
            token_malformed: false,
            userinfo_status: None,
            omit_id_token: false,
            auth_time: AuthTime::IssueTime,
        }
    }
}

const SLOW: Duration = Duration::from_secs(15);

impl Profile {
    pub const ALL: [Profile; 23] = [
        Profile::Default,
        Profile::WrongState,
        Profile::WrongNonce,
        Profile::ExpiredToken,
        Profile::WrongAud,
        Profile::InvalidSignature,
        Profile::UnverifiedEmail,
        Profile::UserinfoWrongSub,
        Profile::HdExampleTest,
        Profile::Oversized,
        Profile::Slow,
        Profile::DiscoveryDown,
        Profile::DiscoveryChangedIssuer,
        Profile::JwksRotated,
        Profile::JwksUnknownKid,
        Profile::Token500,
        Profile::TokenSlow,
        Profile::TokenMalformed,
        Profile::Userinfo500,
        Profile::IdTokenMissing,
        Profile::AuthTimePresent,
        Profile::AuthTimeStale,
        Profile::AuthTimeMissing,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Profile::Default => "default",
            Profile::WrongState => "wrong_state",
            Profile::WrongNonce => "wrong_nonce",
            Profile::ExpiredToken => "expired_token",
            Profile::WrongAud => "wrong_aud",
            Profile::InvalidSignature => "invalid_signature",
            Profile::UnverifiedEmail => "unverified_email",
            Profile::UserinfoWrongSub => "userinfo_wrong_sub",
            Profile::HdExampleTest => "hd_example_test",
            Profile::Oversized => "oversized",
            Profile::Slow => "slow",
            Profile::DiscoveryDown => "discovery_down",
            Profile::DiscoveryChangedIssuer => "discovery_changed_issuer",
            Profile::JwksRotated => "jwks_rotated",
            Profile::JwksUnknownKid => "jwks_unknown_kid",
            Profile::Token500 => "token_500",
            Profile::TokenSlow => "token_slow",
            Profile::TokenMalformed => "token_malformed",
            Profile::Userinfo500 => "userinfo_500",
            Profile::IdTokenMissing => "id_token_missing",
            Profile::AuthTimePresent => "auth_time_present",
            Profile::AuthTimeStale => "auth_time_stale",
            Profile::AuthTimeMissing => "auth_time_missing",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.name() == s)
    }

    pub fn behavior(self) -> Behavior {
        let std = Behavior::standard();
        match self {
            Profile::Default => std,
            Profile::WrongState => Behavior {
                wrong_state: true,
                ..std
            },
            Profile::WrongNonce => Behavior {
                wrong_nonce: true,
                ..std
            },
            Profile::ExpiredToken => Behavior {
                exp_offset_secs: -120,
                ..std
            },
            Profile::WrongAud => Behavior {
                wrong_aud: true,
                ..std
            },
            Profile::InvalidSignature => Behavior {
                rogue_signature: true,
                ..std
            },
            Profile::UnverifiedEmail => Behavior {
                email_verified: false,
                ..std
            },
            Profile::UserinfoWrongSub => Behavior {
                userinfo_sub: Some("sub-2"),
                ..std
            },
            Profile::HdExampleTest => Behavior {
                hd: Some("example.test"),
                ..std
            },
            Profile::Oversized => Behavior {
                oversized: true,
                ..std
            },
            Profile::Slow => Behavior {
                delay_all: Some(SLOW),
                ..std
            },
            Profile::DiscoveryDown => Behavior {
                discovery_status: 503,
                ..std
            },
            Profile::DiscoveryChangedIssuer => Behavior {
                discovery_changes_issuer: true,
                ..std
            },
            Profile::JwksRotated => Behavior {
                jwks_rotates: true,
                ..std
            },
            Profile::JwksUnknownKid => Behavior {
                unknown_kid: true,
                ..std
            },
            Profile::Token500 => Behavior {
                token_status: Some(500),
                ..std
            },
            Profile::TokenSlow => Behavior {
                token_delay: Some(SLOW),
                ..std
            },
            Profile::TokenMalformed => Behavior {
                token_malformed: true,
                ..std
            },
            Profile::Userinfo500 => Behavior {
                userinfo_status: Some(500),
                ..std
            },
            Profile::IdTokenMissing => Behavior {
                omit_id_token: true,
                ..std
            },
            Profile::AuthTimePresent => Behavior {
                auth_time: AuthTime::IssueTime,
                ..std
            },
            Profile::AuthTimeStale => Behavior {
                auth_time: AuthTime::Stale(2 * 86_400),
                ..std
            },
            Profile::AuthTimeMissing => Behavior {
                auth_time: AuthTime::Missing,
                ..std
            },
        }
    }
}
