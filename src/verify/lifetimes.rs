//! The handle and session lifetime state machine (ADR-0007).
//!
//! Handles and sessions have separate timers. A handle timer revokes that
//! handle only; a session timer terminates the session and with it every
//! handle. Session timers are checked first because termination subsumes any
//! handle expiry. All values are compared in milliseconds against `now`; the
//! store keeps whole seconds.

use std::time::Duration;

use crate::crypto::Timestamp;
use crate::event::types::{Reason, reasons};
use crate::policy::types::{Lifetimes, SessionPolicy};
use crate::store::types::{HandleRow, SessionRow};

/// How far ahead of `now` a stored `created_at` may be before the row is
/// treated as written by a clock we cannot trust (S010-A3).
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifetimeVerdict {
    /// Both timers are running. `expires_at` is the earliest of the handle's
    /// idle and absolute deadlines and the session's idle and absolute ones.
    Live { expires_at: Timestamp },
    /// The handle's own timer ran out (`idle` or `absolute`): revoke the handle only.
    HandleExpired(Reason),
    /// The session's timer ran out (`idle` or `absolute`): terminate the session.
    SessionExpired(Reason),
    /// A stored `created_at` lies more than 60 s in the future.
    ClockSkew,
}

/// Evaluate every timer of one handle and its session.
///
/// `app` is the handle's application policy (`apps[].session`); `session` is
/// the session-wide policy. A deadline is the first instant at which the
/// timer has run out.
pub fn evaluate(
    handle: &HandleRow,
    session: &SessionRow,
    app: &Lifetimes,
    policy: &SessionPolicy,
    now: Timestamp,
) -> LifetimeVerdict {
    let tolerance = i64::try_from(CLOCK_SKEW_TOLERANCE.as_millis()).unwrap_or(i64::MAX);
    if handle.created_at.0.saturating_sub(now.0) > tolerance
        || session.created_at.0.saturating_sub(now.0) > tolerance
    {
        return LifetimeVerdict::ClockSkew;
    }
    let session_idle = session.last_seen_at.add(policy.idle);
    let session_abs = session
        .absolute_expires_at
        .min(session.created_at.add(policy.absolute));
    let handle_idle = handle.last_seen_at.add(app.idle);
    let handle_abs = handle
        .absolute_expires_at
        .min(handle.created_at.add(app.absolute));

    if now >= session_abs {
        return LifetimeVerdict::SessionExpired(reasons::ABSOLUTE);
    }
    if now >= session_idle {
        return LifetimeVerdict::SessionExpired(reasons::IDLE);
    }
    if now >= handle_abs {
        return LifetimeVerdict::HandleExpired(reasons::ABSOLUTE);
    }
    if now >= handle_idle {
        return LifetimeVerdict::HandleExpired(reasons::IDLE);
    }
    LifetimeVerdict::Live {
        expires_at: session_idle
            .min(session_abs)
            .min(handle_idle)
            .min(handle_abs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Digest;
    use crate::identity::types::UserId;
    use crate::policy::types::Host;
    use crate::provider::types::ProviderId;
    use crate::session::types::{Aal, SessionId};
    use crate::store::types::IdentitySnapshot;

    const H: u64 = 3600;
    const T0: i64 = 1_700_000_000_000;

    fn at(secs: u64) -> Timestamp {
        Timestamp(T0).add(Duration::from_secs(secs))
    }

    fn rows(handle_seen: u64, session_seen: u64) -> (HandleRow, SessionRow) {
        let session = SessionRow {
            session_id: SessionId::new("s_1"),
            user_id: UserId::new("u_1"),
            provider_id: ProviderId::new("mock"),
            auth_time: at(0),
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
            created_at: at(0),
            last_seen_at: at(session_seen),
            absolute_expires_at: at(30 * 24 * H),
            terminated_at: None,
            terminated_reason: None,
        };
        let handle = HandleRow {
            handle_sha256: Digest([0; 32]),
            session_id: SessionId::new("s_1"),
            host: Host::parse("app.example.test").unwrap(),
            issued_aal: Aal::One,
            created_at: at(0),
            last_seen_at: at(handle_seen),
            absolute_expires_at: at(7 * 24 * H),
            revoked_at: None,
            revoked_reason: None,
        };
        (handle, session)
    }

    fn eval(handle_seen: u64, session_seen: u64, now: u64) -> LifetimeVerdict {
        let (h, s) = rows(handle_seen, session_seen);
        evaluate(
            &h,
            &s,
            &Lifetimes::default(),
            &SessionPolicy::default(),
            at(now),
        )
    }

    #[test]
    fn earliest_deadline_is_reported() {
        assert_eq!(
            eval(11 * H, 11 * H, 11 * H),
            LifetimeVerdict::Live {
                expires_at: at(23 * H)
            }
        );
    }

    #[test]
    fn handle_idle_and_absolute_revoke_only_the_handle() {
        assert_eq!(
            eval(0, H, 12 * H + 1),
            LifetimeVerdict::HandleExpired(reasons::IDLE)
        );
        // Kept alive by activity, the absolute timer still ends the handle.
        let day7 = 7 * 24 * H;
        assert_eq!(
            eval(day7 - H, day7 - H, day7 + 1),
            LifetimeVerdict::HandleExpired(reasons::ABSOLUTE)
        );
    }

    #[test]
    fn session_timers_take_precedence() {
        // All handles idle for 24 h + 1 s: the session ends, not just the handle.
        assert_eq!(
            eval(0, 0, 24 * H + 1),
            LifetimeVerdict::SessionExpired(reasons::IDLE)
        );
        let day30 = 30 * 24 * H;
        assert_eq!(
            eval(day30 - H, day30 - H, day30 + 1),
            LifetimeVerdict::SessionExpired(reasons::ABSOLUTE)
        );
    }

    #[test]
    fn activity_on_another_host_extends_the_session_not_the_handle() {
        // Session newest activity 10 min ago; this handle untouched for 2 h (1 h policy).
        let (h, s) = rows(0, 2 * H - 600);
        let app = Lifetimes {
            idle: Duration::from_secs(H),
            absolute: Duration::from_secs(24 * H),
        };
        assert_eq!(
            evaluate(&h, &s, &app, &SessionPolicy::default(), at(2 * H)),
            LifetimeVerdict::HandleExpired(reasons::IDLE)
        );
    }

    #[test]
    fn clock_skew_tolerance_is_sixty_seconds() {
        let run = |created: u64| {
            let (mut h, s) = rows(0, 0);
            h.created_at = at(created);
            evaluate(
                &h,
                &s,
                &Lifetimes::default(),
                &SessionPolicy::default(),
                at(0),
            )
        };
        assert!(matches!(run(59), LifetimeVerdict::Live { .. }));
        assert!(matches!(run(60), LifetimeVerdict::Live { .. }));
        assert_eq!(run(61), LifetimeVerdict::ClockSkew);
    }
}
