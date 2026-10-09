//! Step-up rules (ADR-0008). Parsed and validated in M1; enforcement is M5.
//! The one effect in M1 is cacheability: a non-empty rule list makes every
//! decision path-dependent, so the engine answers `no-store` (ADR-0006).

use std::time::Duration;

use crate::crypto::Timestamp;
use crate::policy::types::StepUpRule;
use crate::session::types::Aal;

/// True when the rule list makes the decision depend on the path.
pub fn forces_no_store(rules: &[StepUpRule]) -> bool {
    !rules.is_empty()
}

/// A prefix matches on whole path segments: `/admin` covers `/admin` and
/// `/admin/x` but not `/administrator`. A rule without a prefix covers the host.
pub fn rule_matches(rule: &StepUpRule, canonical_path: &str) -> bool {
    match &rule.path_prefix {
        None => true,
        Some(prefix) => {
            let p = prefix.trim_end_matches('/');
            canonical_path == p
                || canonical_path
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('/'))
                || p.is_empty()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepUpVerdict {
    NotRequired,
    Required { aal: Aal, max_age: Option<Duration> },
}

/// What the rules ask of a request. Not called by the M1 engine (no
/// enforcement); exposed for the M5 work and exercised by unit tests.
pub fn evaluate(
    rules: &[StepUpRule],
    canonical_path: &str,
    handle_aal: Aal,
    auth_time: Timestamp,
    now: Timestamp,
) -> StepUpVerdict {
    for rule in rules.iter().filter(|r| rule_matches(r, canonical_path)) {
        let too_old = rule.max_age.is_some_and(|m| now.since(auth_time) > m);
        if handle_aal < rule.aal || too_old {
            return StepUpVerdict::Required {
                aal: rule.aal,
                max_age: rule.max_age,
            };
        }
    }
    StepUpVerdict::NotRequired
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: Option<&str>, aal: Aal, max_age: Option<u64>) -> StepUpRule {
        StepUpRule {
            path_prefix: prefix.map(str::to_string),
            aal,
            max_age: max_age.map(Duration::from_secs),
        }
    }

    #[test]
    fn prefix_matches_whole_segments() {
        let r = rule(Some("/admin"), Aal::Two, None);
        assert!(rule_matches(&r, "/admin"));
        assert!(rule_matches(&r, "/admin/x"));
        assert!(!rule_matches(&r, "/administrator"));
        assert!(!rule_matches(&r, "/"));
        assert!(rule_matches(&rule(None, Aal::Two, None), "/anything"));
    }

    #[test]
    fn verdict_needs_level_and_freshness() {
        let rules = [rule(Some("/admin"), Aal::Two, Some(600))];
        let t0 = Timestamp(1_000_000);
        let now = t0.add(Duration::from_secs(60));
        assert_eq!(
            evaluate(&rules, "/public", Aal::One, t0, now),
            StepUpVerdict::NotRequired
        );
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::One, t0, now),
            StepUpVerdict::Required { aal: Aal::Two, .. }
        ));
        assert_eq!(
            evaluate(&rules, "/admin/x", Aal::Two, t0, now),
            StepUpVerdict::NotRequired
        );
        let later = t0.add(Duration::from_secs(601));
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::Two, t0, later),
            StepUpVerdict::Required { .. }
        ));
        assert!(forces_no_store(&rules));
        assert!(!forces_no_store(&[]));
    }
}
