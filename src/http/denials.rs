//! Denial observation shared by the gateway and the admin listeners (F8):
//! which reason a decision records, and the counted, sampled `verify.denied`
//! event with the right scope.

use std::net::IpAddr;

use crate::event::bus::Emitter;
use crate::event::sampling::Scope;
use crate::event::types::Reason;
use crate::policy::types::AppId;
use crate::session::types::SessionId;
use crate::telemetry::counters;
use crate::verify::types::Decision;

/// The listener's own denial counter, bumped besides the shared
/// `hopae_verify_denied_total` the emitter always counts.
#[derive(Clone, Copy, Debug)]
pub struct DenialCounters {
    /// Metric name, labelled `reason`; `None` for the gateway listener.
    pub per_reason: Option<&'static str>,
}

impl DenialCounters {
    /// The gateway listener has no counter of its own.
    pub const GATEWAY: DenialCounters = DenialCounters { per_reason: None };
    /// The admin listener's `hopae_admin_denied_total{reason}`.
    pub const ADMIN: DenialCounters = DenialCounters {
        per_reason: Some(counters::ADMIN_DENIED_TOTAL),
    };

    fn count(&self, reason: Reason) {
        if let Some(name) = self.per_reason {
            counters::inc(name, &[("reason", reason.0)]);
        }
    }
}

/// The `verify.denied` reason of a decision, when it is a denial: a `Deny`, or
/// a `Login` that refused a presented handle.
pub fn denial_reason(decision: &Decision, cause: Option<Reason>) -> Option<Reason> {
    match decision {
        // The primary reason wins: a bad handle that was then rate limited
        // is still a bad-handle denial.
        Decision::Deny { reason, .. } => Some(cause.unwrap_or(*reason)),
        Decision::Login { cause, .. } | Decision::LogoutEntry { cause, .. } => *cause,
        _ => None,
    }
}

/// Record a denial (counted always, one sampled event per scope and reason).
#[allow(clippy::too_many_arguments)]
pub fn record_denial(
    emitter: Option<&Emitter>,
    counters: &DenialCounters,
    decision: &Decision,
    cause: Option<Reason>,
    client_ip: Option<IpAddr>,
    session: Option<&SessionId>,
    app: Option<&AppId>,
    request_id: &str,
) {
    let (Some(emitter), Some(reason)) = (emitter, denial_reason(decision, cause)) else {
        return;
    };
    counters.count(reason);
    let scope = match (session, client_ip) {
        (Some(s), _) => Scope::Session(s.clone()),
        (None, Some(ip)) => Scope::Ip(ip),
        (None, None) => Scope::None,
    };
    emitter.verify_denied(scope, reason, request_id, |b| {
        let b = match client_ip {
            Some(ip) => b.ip(ip),
            None => b,
        };
        match app {
            Some(a) => b.app(a),
            None => b,
        }
    });
}

/// Record a refusal that is not a verify decision (an untrusted peer): the
/// same counted, sampled observation, scoped to the client address.
pub fn record_refusal(
    emitter: Option<&Emitter>,
    counters: &DenialCounters,
    reason: Reason,
    client_ip: IpAddr,
    app: Option<&AppId>,
    request_id: &str,
) {
    counters.count(reason);
    let Some(emitter) = emitter else {
        return;
    };
    emitter.verify_denied(Scope::Ip(client_ip), reason, request_id, |b| {
        let b = b.ip(client_ip);
        match app {
            Some(a) => b.app(a),
            None => b,
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::types::reasons;
    use crate::verify::types::DenyKind;
    use std::time::Duration;

    #[test]
    fn a_denial_carries_its_cause_over_its_reason() {
        let d = Decision::Deny {
            reason: reasons::RATE_LIMITED,
            kind: DenyKind::Unavailable {
                retry_after: Duration::from_secs(1),
            },
        };
        assert_eq!(denial_reason(&d, None), Some(reasons::RATE_LIMITED));
        assert_eq!(
            denial_reason(&d, Some(reasons::UNKNOWN_HANDLE)),
            Some(reasons::UNKNOWN_HANDLE)
        );
    }
}
