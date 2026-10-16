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
//! a key the console shares, so the console can enforce its own minimum for
//! sign-in and for sensitive actions without trusting anything in between.
//!
//! Wire form: `v1.<base64url(JSON claims)>.<base64url(HMAC-SHA256(key,
//! "hopae-operator-assertion.v1." + <base64url(JSON claims)>))>`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::Timestamp;
use crate::policy::types::AppId;
use crate::session::types::{Aal, FactorEntry, FactorKind};

/// How long an assertion is valid: the console checks it on every request
/// (it re-verifies), so a short life bounds any replay.
pub const ASSERTION_LIFETIME: Duration = Duration::from_secs(60);
/// The audience the console checks.
pub const AUDIENCE: &str = "hangang-console";
const DOMAIN: &str = "hopae-operator-assertion.v1.";

/// The claims of an operator assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub v: u8,
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
    key: Vec<u8>,
}

impl std::fmt::Debug for OperatorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorRuntime")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

fn mac(key: &[u8], payload: &str) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key");
    m.update(DOMAIN.as_bytes());
    m.update(payload.as_bytes());
    m
}

impl OperatorRuntime {
    /// The policy of `cfg`, with its key from the environment (`check_env`
    /// refused a start without it).
    pub fn from_config(
        cfg: &crate::config::Config,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Option<Arc<OperatorRuntime>> {
        let c = cfg.console_operators.as_ref()?;
        let key = lookup(&c.assertion_key_env).filter(|k| (32..=4096).contains(&k.len()))?;
        Some(Arc::new(OperatorRuntime {
            app_id: AppId::new(c.app_id.clone()),
            require_aal: c.require_aal(),
            require_webauthn: c.require_factor == crate::config::OperatorFactorCfg::Webauthn,
            grace_until: c.enrollment_grace_until.map(Timestamp::from_secs),
            key: key.into_bytes(),
        }))
    }

    pub fn new(
        app_id: &str,
        require_aal: Aal,
        require_webauthn: bool,
        grace_until: Option<Timestamp>,
        key: &[u8],
    ) -> OperatorRuntime {
        OperatorRuntime {
            app_id: AppId::new(app_id),
            require_aal,
            require_webauthn,
            grace_until,
            key: key.to_vec(),
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
            v: 1,
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
        let tag = URL_SAFE_NO_PAD.encode(mac(&self.key, &payload).finalize().into_bytes());
        format!("v1.{payload}.{tag}")
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

/// Check an assertion (the console's side, also used by tests): format,
/// signature in constant time, audience and lifetime (`now` within
/// `[iat - 5 s, exp]`).
pub fn verify(key: &[u8], token: &str, now: i64) -> Result<Claims, Refused> {
    if token.len() > 4096 {
        return Err(Refused::Malformed);
    }
    let mut parts = token.split('.');
    let (Some("v1"), Some(payload), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refused::Malformed);
    };
    let tag = URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| Refused::Malformed)?;
    mac(key, payload)
        .verify_slice(&tag)
        .map_err(|_| Refused::Signature)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Refused::Malformed)?;
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Refused::Malformed)?;
    if claims.v != 1 || claims.aud != AUDIENCE {
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

    const KEY: &[u8] = b"operator-assertion-key-of-at-least-32-bytes";

    fn entry(kind: FactorKind, at: i64) -> FactorEntry {
        FactorEntry {
            kind,
            provider: None,
            at: Timestamp::from_secs(at),
        }
    }

    #[test]
    fn assertions_are_signed_short_lived_and_state_the_factor() {
        let rt = OperatorRuntime::new("console", Aal::Two, true, None, KEY);
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
        let c = verify(KEY, &t, 1_000).unwrap();
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
        assert!(verify(KEY, &forged, 1_000).is_err());
        assert_eq!(
            verify(b"another-key-of-at-least-thirty-two-bytes!", &t, 1_000),
            Err(Refused::Signature)
        );
        assert_eq!(verify(KEY, &t, 1_061), Err(Refused::Expired));
        assert_eq!(verify(KEY, "v2.a.b", 1_000), Err(Refused::Malformed));
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
        let c = verify(KEY, &t, 1_000).unwrap();
        assert_eq!((c.factor.as_deref(), c.satisfied), (Some("totp"), false));
        // AAL 3 needs the high-assurance evidence.
        let rt3 = OperatorRuntime::new("console", Aal::Three, true, None, KEY);
        let ok = |ha| {
            verify(
                KEY,
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
        let rt = OperatorRuntime::new("c", Aal::Two, true, Some(Timestamp::from_secs(100)), KEY);
        assert!(rt.grace_active(Timestamp::from_secs(99)));
        assert!(!rt.grace_active(Timestamp::from_secs(100)));
    }
}
