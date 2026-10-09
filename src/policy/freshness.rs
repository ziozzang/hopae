//! The freshness predicate (ADR-0016 decision 15, P2-08): one function, used
//! by the verify engine at every console verify and — in SQL form — by the
//! store's actor fence.

use std::time::Duration;

use crate::crypto::Timestamp;
use crate::event::types::{Reason, reasons};
use crate::provider::types::ReauthCapability;
use crate::store::types::{AuthTimeSource, SessionRow};

/// Tolerance for an `auth_time` (or a handle) slightly ahead of this clock.
pub const FRESHNESS_SKEW: Duration = Duration::from_secs(60);

/// Headroom a reauthentication callback must leave so the first console
/// verify after the handoff is still fresh. Configuration validation:
/// `admin.max_auth_age >= 30m` (P3-05); 60 s is a rejection test.
pub const MIN_MAX_AUTH_AGE: Duration = Duration::from_secs(1800);

/// The oldest `auth_time` a reauthentication callback may carry for bound `n`:
/// always at least 1200 s for a permitted `n`, never a branch.
pub fn callback_bound(n: Duration) -> Duration {
    n.saturating_sub(Duration::from_secs(600))
}

/// `auth_time <= now + 60 s  AND  now - auth_time < n` (an age equal to `n`
/// is NOT fresh). Whole seconds, the same arithmetic the SQL uses:
/// `s.auth_time <= :now + :skew AND :now - s.auth_time < :max_auth_age`.
pub fn is_fresh(auth_time: Timestamp, now: Timestamp, n: Duration) -> bool {
    let (a, now) = (auth_time.secs(), now.secs());
    let skew = i64::try_from(FRESHNESS_SKEW.as_secs()).unwrap_or(i64::MAX);
    let n = i64::try_from(n.as_secs()).unwrap_or(i64::MAX);
    a <= now.saturating_add(skew) && now.saturating_sub(a) < n
}

/// What the console demands of a session, by its provider's capability: with
/// a `max_age` provider the age must come from a provider-verified claim;
/// with an `unsupported` one Hopae login age is all there is.
pub fn console_fresh(
    session: &SessionRow,
    capability: ReauthCapability,
    now: Timestamp,
    n: Duration,
) -> bool {
    match capability {
        ReauthCapability::MaxAge => {
            session.auth_time_source == AuthTimeSource::ProviderClaim
                && is_fresh(session.auth_time, now, n)
        }
        ReauthCapability::Unsupported => is_fresh(session.auth_time, now, n),
    }
}

/// A present claim must be a valid integer and not later than `now + 60 s`; an
/// invalid one FAILS the login (never replaced by `now`). This is the only
/// place an `auth_time` claim is interpreted.
pub fn validate_claim(
    claim: Option<&serde_json::Value>,
    now: Timestamp,
) -> Result<Option<Timestamp>, Reason> {
    let Some(v) = claim else {
        return Ok(None);
    };
    let secs = v
        .as_i64()
        .filter(|s| *s > 0)
        .ok_or(reasons::INVALID_AUTH_TIME)?;
    let limit = now
        .secs()
        .saturating_add(i64::try_from(FRESHNESS_SKEW.as_secs()).unwrap_or(i64::MAX));
    if secs > limit {
        return Err(reasons::INVALID_AUTH_TIME);
    }
    Ok(Some(Timestamp::from_secs(secs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const N: Duration = Duration::from_secs(12 * 3600);

    fn ts(s: i64) -> Timestamp {
        Timestamp::from_secs(s)
    }

    /// The SQL the actor fence uses, on the same numbers.
    fn sql_fresh(auth: i64, now: i64, n: i64) -> bool {
        let c = Connection::open_in_memory().unwrap();
        c.query_row(
            "SELECT :auth <= :now + :skew AND :now - :auth < :n",
            rusqlite::named_params! {":auth": auth, ":now": now, ":skew": 60, ":n": n},
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn boundaries_of_scenario_300_a10_agree_between_rust_and_sql() {
        let n = N.as_secs() as i64;
        for (age, fresh) in [
            (0, true),
            (n - 1, true),
            (n, false), // equality is not fresh
            (n + 1, false),
            (-59, true), // a claim up to 60 s ahead is tolerated
            (-60, true),
            (-61, false),
        ] {
            let auth = NOW - age;
            assert_eq!(is_fresh(ts(auth), ts(NOW), N), fresh, "age {age}");
            assert_eq!(sql_fresh(auth, NOW, n), fresh, "sql, age {age}");
        }
    }

    #[test]
    fn claims_are_validated_once_and_never_replaced() {
        let now = ts(NOW);
        assert_eq!(validate_claim(None, now), Ok(None));
        assert_eq!(
            validate_claim(Some(&json!(NOW - 100)), now),
            Ok(Some(ts(NOW - 100)))
        );
        assert_eq!(
            validate_claim(Some(&json!(NOW + 59)), now),
            Ok(Some(ts(NOW + 59)))
        );
        assert_eq!(
            validate_claim(Some(&json!(NOW + 60)), now),
            Ok(Some(ts(NOW + 60)))
        );
        for bad in [
            json!(NOW + 61),
            json!(-5),
            json!(0),
            json!("1700000000"),
            json!(1.5),
            json!(null),
            json!(true),
            json!([NOW]),
            json!({"t": NOW}),
            json!(u64::MAX),
        ] {
            assert_eq!(
                validate_claim(Some(&bad), now),
                Err(reasons::INVALID_AUTH_TIME),
                "{bad}"
            );
        }
    }

    fn session(auth: i64, source: AuthTimeSource) -> SessionRow {
        use crate::identity::types::UserId;
        use crate::provider::types::ProviderId;
        use crate::session::types::{Aal, SessionId};
        use crate::store::types::IdentitySnapshot;
        SessionRow {
            session_id: SessionId::new("s_1"),
            user_id: UserId::new("u_1"),
            provider_id: ProviderId::new("mock"),
            auth_time: ts(auth),
            factors: vec![],
            aal: Aal::One,
            authz_version: 1,
            cred_gen: 1,
            snapshot: IdentitySnapshot {
                email: None,
                display_name: None,
                username: None,
                groups: vec![],
            },
            bound_ip: "192.0.2.1".parse().unwrap(),
            bound_ua_sha256: None,
            created_at: ts(auth),
            last_seen_at: ts(auth),
            absolute_expires_at: ts(auth + 100_000),
            terminated_at: None,
            terminated_reason: None,
            authz_version_at_auth: 1,
            auth_time_source: source,
            bound_ua_prefix: None,
        }
    }

    #[test]
    fn the_capability_decides_what_counts_as_evidence() {
        let claim = session(NOW - 60, AuthTimeSource::ProviderClaim);
        let local = session(NOW - 60, AuthTimeSource::HopaeCompletion);
        for cap in [ReauthCapability::MaxAge, ReauthCapability::Unsupported] {
            assert!(
                console_fresh(&claim, cap, ts(NOW), N),
                "{cap:?}: a provider claim is evidence either way"
            );
        }
        assert!(
            !console_fresh(&local, ReauthCapability::MaxAge, ts(NOW), N),
            "max_age provider: Hopae login time is not evidence"
        );
        assert!(
            console_fresh(&local, ReauthCapability::Unsupported, ts(NOW), N),
            "unsupported provider: Hopae login age is all there is"
        );
        let stale = session(NOW - N.as_secs() as i64, AuthTimeSource::ProviderClaim);
        assert!(!console_fresh(&stale, ReauthCapability::MaxAge, ts(NOW), N));
        assert!(!console_fresh(
            &stale,
            ReauthCapability::Unsupported,
            ts(NOW),
            N
        ));
    }

    #[test]
    fn the_callback_bound_keeps_a_headroom_that_is_never_a_branch() {
        assert_eq!(
            callback_bound(Duration::from_secs(1800)),
            Duration::from_secs(1200)
        );
        assert_eq!(callback_bound(N), Duration::from_secs(12 * 3600 - 600));
        assert!(callback_bound(MIN_MAX_AUTH_AGE) >= Duration::from_secs(1200));
        assert_eq!(FRESHNESS_SKEW, Duration::from_secs(60));
    }
}
