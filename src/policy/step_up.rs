//! Step-up evidence and freshness requirements (ADR-0008).
//! AAL 2 needs an issued level and an actual second-factor record.

use std::time::Duration;

use crate::crypto::Timestamp;
use crate::policy::types::StepUpRule;
use crate::session::types::{Aal, FactorEntry, FactorKind};

/// True when the rule list makes the decision depend on the path.
pub fn forces_no_store(rules: &[StepUpRule]) -> bool {
    !rules.is_empty()
}

/// A prefix matches on whole path segments, ASCII-case-insensitively: `/admin` covers `/admin` and
/// `/admin/x` but not `/administrator`. A rule without a prefix covers the host.
pub fn rule_matches(rule: &StepUpRule, canonical_path: &str) -> bool {
    match &rule.path_prefix {
        None => true,
        Some(prefix) => {
            // ASCII-case-insensitive (TM-39): an upstream that folds case
            // serves `/ADMIN/x` as `/admin/x`, so the rule must too.
            let prefix = prefix.trim_end_matches('/').as_bytes();
            let path = canonical_path.as_bytes();
            // Byte-wise ASCII comparison preserves UTF-8 equality without
            // allocating lowercase copies for every rule on every request.
            prefix.is_empty()
                || (path
                    .get(..prefix.len())
                    .is_some_and(|segment| segment.eq_ignore_ascii_case(prefix))
                    && path.get(prefix.len()).is_none_or(|next| *next == b'/'))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepUpVerdict {
    NotRequired,
    Required { aal: Aal, max_age: Option<Duration> },
}

/// Evaluate every matching rule. A second-factor freshness bound uses the
/// latest actual factor satisfaction, never the primary login timestamp.
pub fn evaluate(
    rules: &[StepUpRule],
    canonical_path: &str,
    handle_aal: Aal,
    auth_time: Timestamp,
    factors: &[FactorEntry],
    now: Timestamp,
) -> StepUpVerdict {
    for rule in rules.iter().filter(|r| rule_matches(r, canonical_path)) {
        let satisfied_at = if rule.aal == Aal::Two {
            let second_factors = factors.iter().filter(|f| {
                matches!(
                    f.kind,
                    FactorKind::Totp | FactorKind::Webauthn | FactorKind::Recovery
                )
            });
            let mut latest = None;
            for factor in second_factors {
                if factor.at > now {
                    latest = None;
                    break;
                }
                latest = Some(latest.map_or(factor.at, |at: Timestamp| at.max(factor.at)));
            }
            latest
        } else {
            (auth_time <= now).then_some(auth_time)
        };
        let insufficient_evidence =
            satisfied_at.is_none_or(|at| rule.max_age.is_some_and(|m| now.since(at) > m));
        if handle_aal < rule.aal || insufficient_evidence {
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
    fn prefix_comparison_is_ascii_case_insensitive() {
        // TM-39: a case-insensitive upstream serves `/ADMIN/x` as `/admin/x`.
        let r = rule(Some("/admin"), Aal::Two, None);
        for p in ["/ADMIN", "/Admin/x", "/aDmIn/x/y"] {
            assert!(rule_matches(&r, p), "{p}");
        }
        assert!(!rule_matches(&r, "/ADMINISTRATOR"));
        let upper = rule(Some("/ADMIN/"), Aal::Two, None);
        assert!(rule_matches(&upper, "/admin/x"));
        // Only ASCII folds: a non-ASCII letter is not case-mapped.
        let k = rule(Some("/\u{c9}t\u{e9}"), Aal::Two, None);
        assert!(rule_matches(&k, "/\u{c9}T\u{e9}/x") && !rule_matches(&k, "/\u{e9}t\u{e9}/x"));
    }

    #[test]
    fn verdict_needs_level_and_freshness() {
        let rules = [rule(Some("/admin"), Aal::Two, Some(600))];
        let t0 = Timestamp(1_000_000);
        let now = t0.add(Duration::from_secs(60));
        let factors = [FactorEntry {
            kind: FactorKind::Totp,
            provider: None,
            at: t0,
        }];
        assert_eq!(
            evaluate(&rules, "/public", Aal::One, t0, &factors, now),
            StepUpVerdict::NotRequired
        );
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::One, t0, &factors, now),
            StepUpVerdict::Required { aal: Aal::Two, .. }
        ));
        assert_eq!(
            evaluate(&rules, "/admin/x", Aal::Two, t0, &factors, now),
            StepUpVerdict::NotRequired
        );
        let later = t0.add(Duration::from_secs(601));
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::Two, t0, &factors, later),
            StepUpVerdict::Required { .. }
        ));
        assert!(forces_no_store(&rules));
        assert!(!forces_no_store(&[]));
    }
}
