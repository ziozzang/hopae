//! Untrusted external-factor response validation, without session authority.
//! Transport authentication, durable challenge consumption and session elevation
//! must be implemented by the caller before an external factor can be enabled.
use crate::crypto::Timestamp;
use serde::Deserialize;
use std::{fmt, time::Duration};

/// Trusted, server-owned challenge bindings. Never construct from browser claims.
pub struct Expected<'a> {
    pub challenge: &'a str,
    pub user: &'a str,
    pub session: &'a str,
    pub service: &'a str,
    pub factor: &'a str,
    pub configuration_revision: u64,
    pub credential_generation: u64,
    pub started_at: Timestamp,
    pub challenge_expires_at: Timestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response<'a> {
    active: bool,
    challenge: &'a str,
    user: &'a str,
    session: &'a str,
    service: &'a str,
    factor: &'a str,
    configuration_revision: u64,
    credential_generation: u64,
    proof_id: &'a str,
    expires_at: Timestamp,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidResponse;

/// Parsed evidence only: not serializable and not a session/AAL grant.
pub struct Evidence {
    proof_id: String,
    expires_at: Timestamp,
}
impl Evidence {
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}
impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Evidence([REDACTED])")
    }
}

#[derive(Debug)]
pub enum Decision {
    Rejected,
    Verified(Evidence),
}

/// Call only after authenticating the configured verifier's transport.
/// The five-second maximum includes transport time, measured monotonically.
/// Unknown/duplicate fields and caller-selected identities or assurance fail.
pub fn validate(
    bytes: &[u8],
    expected: &Expected<'_>,
    received_at: Timestamp,
    elapsed: Duration,
) -> Result<Decision, InvalidResponse> {
    if bytes.len() > 8192
        || elapsed > Duration::from_secs(5)
        || received_at < expected.started_at
        || expected.configuration_revision == 0
        || expected.challenge_expires_at <= received_at
    {
        return Err(InvalidResponse);
    }
    let response: Response<'_> = serde_json::from_slice(bytes).map_err(|_| InvalidResponse)?;
    let bindings = [
        (response.challenge, expected.challenge),
        (response.user, expected.user),
        (response.session, expected.session),
        (response.service, expected.service),
        (response.factor, expected.factor),
    ];
    if bindings
        .iter()
        .any(|(actual, wanted)| actual != wanted || !bounded_identifier(actual))
        || !bounded_identifier(response.proof_id)
        || response.configuration_revision != expected.configuration_revision
        || response.credential_generation != expected.credential_generation
        || response.expires_at <= received_at
        || response.expires_at > expected.started_at.add(Duration::from_secs(5))
        || response.expires_at > expected.challenge_expires_at
    {
        return Err(InvalidResponse);
    }
    if !response.active {
        return Ok(Decision::Rejected);
    }
    Ok(Decision::Verified(Evidence {
        proof_id: response.proof_id.to_owned(),
        expires_at: response.expires_at,
    }))
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Expected<'static> {
        Expected {
            challenge: "c_test",
            user: "u_test",
            session: "s_test",
            service: "orders",
            factor: "partner-push",
            configuration_revision: 7,
            credential_generation: 3,
            started_at: Timestamp(1000),
            challenge_expires_at: Timestamp(10000),
        }
    }
    fn response() -> serde_json::Value {
        serde_json::json!({"active":true,"challenge":"c_test","user":"u_test",
            "session":"s_test","service":"orders","factor":"partner-push",
            "configuration_revision":7,"credential_generation":3,
            "proof_id":"proof_once","expires_at":4000})
    }
    fn check(value: &serde_json::Value) -> Result<Decision, InvalidResponse> {
        validate(
            &serde_json::to_vec(value).unwrap(),
            &expected(),
            Timestamp(2000),
            Duration::from_secs(1),
        )
    }
    #[test]
    fn accepts_bound_evidence_and_explicit_rejection_without_granting_assurance() {
        let Decision::Verified(evidence) = check(&response()).unwrap() else {
            panic!("expected evidence")
        };
        assert_eq!(evidence.proof_id(), "proof_once");
        assert_eq!(evidence.expires_at(), Timestamp(4000));
        assert!(!format!("{evidence:?}").contains("proof_once"));
        let mut denied = response();
        denied["active"] = false.into();
        assert!(matches!(check(&denied), Ok(Decision::Rejected)));
    }
    #[test]
    fn rejects_cross_scope_stale_generation_and_verifier_selected_assurance() {
        for field in [
            "challenge",
            "user",
            "session",
            "service",
            "factor",
            "configuration_revision",
            "credential_generation",
        ] {
            let mut value = response();
            value[field] = if value[field].is_number() {
                99.into()
            } else {
                "other".into()
            };
            assert!(check(&value).is_err(), "{field}");
        }
        for field in ["aal", "role", "permissions", "issuer", "headers"] {
            let mut value = response();
            value[field] = 2.into();
            assert!(check(&value).is_err(), "{field}");
        }
        let mut value = response();
        value["active"] = false.into();
        value["user"] = "other".into();
        assert!(check(&value).is_err());
    }
    #[test]
    fn bounds_time_body_identifiers_and_duplicate_fields() {
        for expires in [0, 2000, 6001, i64::MAX] {
            let mut value = response();
            value["expires_at"] = expires.into();
            assert!(check(&value).is_err());
        }
        for proof in ["", "bad\nproof", &"a".repeat(257)] {
            let mut value = response();
            value["proof_id"] = proof.into();
            assert!(check(&value).is_err());
        }
        let bytes = serde_json::to_vec(&response()).unwrap();
        assert!(validate(&bytes, &expected(), Timestamp(999), Duration::ZERO).is_err());
        assert!(
            validate(
                &bytes,
                &expected(),
                Timestamp(2000),
                Duration::from_millis(5001)
            )
            .is_err()
        );
        let mut expired = expected();
        expired.challenge_expires_at = Timestamp(3000);
        assert!(validate(&bytes, &expired, Timestamp(2000), Duration::ZERO).is_err());
        let mut disabled = expected();
        disabled.configuration_revision = 0;
        assert!(validate(&bytes, &disabled, Timestamp(2000), Duration::ZERO).is_err());
        assert!(validate(&[b' '; 8193], &expected(), Timestamp(2000), Duration::ZERO).is_err());
        let text = String::from_utf8(bytes)
            .unwrap()
            .replacen("{", "{\"active\":false,", 1);
        assert!(
            validate(
                text.as_bytes(),
                &expected(),
                Timestamp(2000),
                Duration::ZERO
            )
            .is_err()
        );
    }
}
