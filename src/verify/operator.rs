//! Console operator assurance (ADR-0021): the policy a management console's
//! application carries and the signed operator assertion verify answers with.
//!
//! A management console (the Hangang console) signs its operators in through
//! a Hopae application (`console_operators.app_id`). That application gets
//! step-up rules from the policy (the required level and factor on the whole
//! host, waivable during the enrollment grace for an operator without a
//! passkey; the same with freshness on the step-up path), and every allowed
//! verify for it carries `x-hopae-operator-assertion`: a short-lived claim of
//! the session's level and the factor that established it, HMAC-signed with
//! Hopae's dedicated Ed25519 key (the console pins the public key, the
//! current and the next one during a rotation), so the console can enforce its own minimum for
//! sign-in and for sensitive actions without trusting anything in between.
//!
//! Wire form: `v2.<base64url(JSON claims)>.<base64url(Ed25519 signature over
//! "hopae-operator-assertion.v2." + <base64url(JSON claims)>)>`; the claims
//! name the signing key (`kid`).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::Timestamp;
use crate::policy::types::AppId;
use crate::session::types::{Aal, FactorEntry, FactorKind};

/// How long an assertion is valid: the console checks it on every request
/// (it re-verifies), so a short life bounds any replay.
pub const ASSERTION_LIFETIME: Duration = Duration::from_secs(60);
/// The audience the console checks.
pub const AUDIENCE: &str = "hangang-console";
const DOMAIN: &str = "hopae-operator-assertion.v2.";

/// The claims of an operator assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub v: u8,
    /// The signing key's id (the console pins the public key under it).
    pub kid: String,
    pub aud: String,
    /// The console application and the host the request was for.
    pub app: String,
    pub host: String,
    /// The Hopae user and session.
    pub sub: String,
    pub sid: String,
    /// The level presented to the console (1 to 3).
    pub aal: u8,
    /// The latest second factor (`webauthn`, `totp`, `external`), if any.
    pub factor: Option<String>,
    /// When that factor was used (unix seconds).
    pub factor_at: Option<i64>,
    /// The session's current elevation is a high-assurance passkey.
    pub high_assurance: bool,
    pub auth_time: i64,
    /// The policy: required level and factor (`webauthn` or `any`).
    pub require_aal: u8,
    pub require_factor: String,
    /// The session meets the policy (level and factor).
    pub satisfied: bool,
    /// Admitted without the factor during the enrollment grace.
    pub grace: bool,
    pub iat: i64,
    pub exp: i64,
}

/// The console operator policy as verify applies it.
pub struct OperatorRuntime {
    pub app_id: AppId,
    pub require_aal: Aal,
    pub require_webauthn: bool,
    pub grace_until: Option<Timestamp>,
    key: SigningKey,
    kid: String,
}

impl std::fmt::Debug for OperatorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorRuntime")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

fn signed_bytes(payload: &str) -> Vec<u8> {
    [DOMAIN.as_bytes(), payload.as_bytes()].concat()
}

/// A base64 (standard) Ed25519 seed (32 bytes) or public key.
fn key_bytes(value: &str) -> Option<Zeroizing<[u8; 32]>> {
    use base64::engine::general_purpose::STANDARD;
    let bytes = Zeroizing::new(STANDARD.decode(value.trim().as_bytes()).ok()?);
    Some(Zeroizing::new(bytes.as_slice().try_into().ok()?))
}

/// The signing key of `console_operators`: the seed from the environment,
/// matching the pinned public key. Errors name the problem, never the seed.
pub fn signing_key(
    cfg: &crate::config::ConsoleOperatorsCfg,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<SigningKey, String> {
    let seed = lookup(&cfg.assertion_seed_env)
        .and_then(|v| key_bytes(&v))
        .ok_or_else(|| {
            format!(
                "environment variable {} (console_operators.assertion_seed_env) is not a base64 Ed25519 seed",
                cfg.assertion_seed_env
            )
        })?;
    let key = SigningKey::from_bytes(&seed);
    let pinned = key_bytes(&cfg.assertion_public_key)
        .ok_or("console_operators.assertion_public_key is not a base64 Ed25519 public key")?;
    if key.verifying_key().to_bytes() != *pinned {
        return Err("console_operators.assertion_public_key does not match the seed".into());
    }
    Ok(key)
}

impl OperatorRuntime {
    /// The policy of `cfg`, with its key from the environment (`check_env`
    /// refused a start without it).
    pub fn from_config(
        cfg: &crate::config::Config,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Option<Arc<OperatorRuntime>> {
        let c = cfg.console_operators.as_ref()?;
        let key = signing_key(c, lookup).ok()?;
        Some(Arc::new(OperatorRuntime {
            app_id: AppId::new(c.app_id.clone()),
            require_aal: c.require_aal(),
            require_webauthn: c.require_factor == crate::config::OperatorFactorCfg::Webauthn,
            grace_until: c.enrollment_grace_until.map(Timestamp::from_secs),
            key,
            kid: c.assertion_key_id.clone(),
        }))
    }

    pub fn new(
        app_id: &str,
        require_aal: Aal,
        require_webauthn: bool,
        grace_until: Option<Timestamp>,
        key: SigningKey,
        kid: &str,
    ) -> OperatorRuntime {
        OperatorRuntime {
            app_id: AppId::new(app_id),
            require_aal,
            require_webauthn,
            grace_until,
            key,
            kid: kid.to_string(),
        }
    }

    pub fn grace_active(&self, now: Timestamp) -> bool {
        self.grace_until.is_some_and(|until| now < until)
    }

    /// The signed assertion for an allowed console request.
    #[allow(clippy::too_many_arguments)]
    pub fn assertion(
        &self,
        host: &str,
        user: &str,
        session: &str,
        presented: Aal,
        factors: &[FactorEntry],
        high_assurance: bool,
        auth_time: Timestamp,
        grace: bool,
        now: Timestamp,
    ) -> String {
        let latest = factors
            .iter()
            .filter(|f| {
                matches!(
                    f.kind,
                    FactorKind::Webauthn | FactorKind::Totp | FactorKind::External
                )
            })
            .max_by_key(|f| f.at);
        let factor_ok =
            !self.require_webauthn || latest.is_some_and(|f| f.kind == FactorKind::Webauthn);
        let level_ok = match self.require_aal {
            Aal::Three => high_assurance && presented >= Aal::Two,
            required => presented >= required,
        };
        let claims = Claims {
            v: 2,
            kid: self.kid.clone(),
            aud: AUDIENCE.into(),
            app: self.app_id.to_string(),
            host: host.to_string(),
            sub: user.to_string(),
            sid: session.to_string(),
            aal: if high_assurance && presented >= Aal::Two {
                3
            } else {
                presented.as_i64() as u8
            },
            factor: latest.map(|f| f.kind.as_str().to_string()),
            factor_at: latest.map(|f| f.at.secs()),
            high_assurance,
            auth_time: auth_time.secs(),
            require_aal: self.require_aal.as_i64() as u8,
            require_factor: if self.require_webauthn {
                "webauthn".into()
            } else {
                "any".into()
            },
            satisfied: factor_ok && level_ok,
            grace,
            iat: now.secs(),
            exp: now.secs() + ASSERTION_LIFETIME.as_secs() as i64,
        };
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
        let sig = self.key.sign(&signed_bytes(&payload));
        format!("v2.{payload}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

/// Why an assertion was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Malformed,
    Signature,
    Expired,
    Audience,
}

/// Check an assertion (the console's side, also used by tests): format, the
/// Ed25519 signature under the pinned key its `kid` names (the current and
/// the next key during a rotation), audience and lifetime (`now` within
/// `[iat - 5 s, exp]`).
pub fn verify(keys: &[(&str, VerifyingKey)], token: &str, now: i64) -> Result<Claims, Refused> {
    if token.len() > 4096 {
        return Err(Refused::Malformed);
    }
    let mut parts = token.split('.');
    let (Some("v2"), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refused::Malformed);
    };
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| Refused::Malformed)?;
    let sig = Signature::from_slice(&sig).map_err(|_| Refused::Malformed)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Refused::Malformed)?;
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Refused::Malformed)?;
    let key = keys
        .iter()
        .find(|(kid, _)| *kid == claims.kid)
        .ok_or(Refused::Signature)?;
    key.1
        .verify(&signed_bytes(payload), &sig)
        .map_err(|_| Refused::Signature)?;
    if claims.v != 2 || claims.aud != AUDIENCE {
        return Err(Refused::Audience);
    }
    if now > claims.exp || now + 5 < claims.iat {
        return Err(Refused::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32])
    }
    fn pinned() -> Vec<(&'static str, VerifyingKey)> {
        vec![("k1", key().verifying_key())]
    }

    fn entry(kind: FactorKind, at: i64) -> FactorEntry {
        FactorEntry {
            kind,
            provider: None,
            at: Timestamp::from_secs(at),
        }
    }

    #[test]
    fn assertions_are_signed_short_lived_and_state_the_factor() {
        let rt = OperatorRuntime::new("console", Aal::Two, true, None, key(), "k1");
        let now = Timestamp::from_secs(1_000);
        let factors = [
            entry(FactorKind::Oidc, 900),
            entry(FactorKind::Webauthn, 950),
            entry(FactorKind::Totp, 940),
        ];
        let t = rt.assertion(
            "console.example.test",
            "u_a",
            "s_a",
            Aal::Two,
            &factors,
            false,
            Timestamp::from_secs(900),
            false,
            now,
        );
        let c = verify(&pinned(), &t, 1_000).unwrap();
        assert_eq!(
            (c.aal, c.factor.as_deref(), c.factor_at, c.satisfied),
            (2, Some("webauthn"), Some(950), true)
        );
        assert_eq!(
            (c.sub.as_str(), c.sid.as_str(), c.app.as_str()),
            ("u_a", "s_a", "console")
        );
        // Tampering, another key, expiry.
        let mut forged = t.clone();
        forged.replace_range(5..6, if &t[5..6] == "A" { "B" } else { "A" });
        assert!(verify(&pinned(), &forged, 1_000).is_err());
        let other = SigningKey::from_bytes(&[12; 32]).verifying_key();
        assert_eq!(verify(&[("k1", other)], &t, 1_000), Err(Refused::Signature));
        assert_eq!(
            verify(&[("k0", other), ("k1", key().verifying_key())], &t, 1_000).map(|c| c.kid),
            Ok("k1".to_string()),
            "the next key pinned beside the current one"
        );
        assert_eq!(
            verify(&[("k2", key().verifying_key())], &t, 1_000),
            Err(Refused::Signature)
        );
        assert_eq!(verify(&pinned(), &t, 1_061), Err(Refused::Expired));
        assert_eq!(verify(&pinned(), "v1.a.b", 1_000), Err(Refused::Malformed));
        // A TOTP-elevated session does not meet a webauthn policy.
        let t = rt.assertion(
            "h",
            "u",
            "s",
            Aal::Two,
            &[entry(FactorKind::Totp, 990)],
            false,
            now,
            false,
            now,
        );
        let c = verify(&pinned(), &t, 1_000).unwrap();
        assert_eq!((c.factor.as_deref(), c.satisfied), (Some("totp"), false));
        // AAL 3 needs the high-assurance evidence.
        let rt3 = OperatorRuntime::new("console", Aal::Three, true, None, key(), "k1");
        let ok = |ha| {
            verify(
                &pinned(),
                &rt3.assertion(
                    "h",
                    "u",
                    "s",
                    Aal::Two,
                    &[entry(FactorKind::Webauthn, 990)],
                    ha,
                    now,
                    false,
                    now,
                ),
                1_000,
            )
            .unwrap()
        };
        assert_eq!((ok(true).aal, ok(true).satisfied), (3, true));
        assert_eq!((ok(false).aal, ok(false).satisfied), (2, false));
    }

    #[test]
    fn the_grace_window_is_bounded() {
        let rt = OperatorRuntime::new(
            "c",
            Aal::Two,
            true,
            Some(Timestamp::from_secs(100)),
            key(),
            "k1",
        );
        assert!(rt.grace_active(Timestamp::from_secs(99)));
        assert!(!rt.grace_active(Timestamp::from_secs(100)));
    }
}
