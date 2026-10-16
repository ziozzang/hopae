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

/// The highest level a rule matching `canonical_path` requires, if any.
pub fn required_level(rules: &[StepUpRule], canonical_path: &str) -> Option<Aal> {
    rules
        .iter()
        .filter(|r| rule_matches(r, canonical_path))
        .map(|r| r.aal)
        .max()
}

/// The latest satisfaction of one of `kinds`, `None` when there is none or
/// any of them lies in the future (clock skew is refused, not trusted).
fn latest_of(factors: &[FactorEntry], kinds: &[FactorKind], now: Timestamp) -> Option<Timestamp> {
    let mut latest = None;
    for factor in factors.iter().filter(|f| kinds.contains(&f.kind)) {
        if factor.at > now {
            return None;
        }
        latest = Some(latest.map_or(factor.at, |at: Timestamp| at.max(factor.at)));
    }
    latest
}

/// Evaluate every matching rule. A second-factor freshness bound uses the
/// latest actual factor satisfaction, never the primary login timestamp.
///
/// An AAL 3 rule (ADR-0018) needs an AAL 2 handle **and** `aal3`: the
/// caller's evidence that the session's current elevation is a qualifying
/// high-assurance passkey (attested, allowlisted, not synchronized, still
/// active). Its freshness is the latest passkey use, which is that
/// elevation's (any later elevation replaces the evidence).
pub fn evaluate(
    rules: &[StepUpRule],
    canonical_path: &str,
    handle_aal: Aal,
    aal3: bool,
    auth_time: Timestamp,
    factors: &[FactorEntry],
    now: Timestamp,
) -> StepUpVerdict {
    for rule in rules.iter().filter(|r| rule_matches(r, canonical_path)) {
        let satisfied_at = match rule.aal {
            // A recovery code is AAL 1 evidence only: it never satisfies or
            // refreshes an AAL 2 rule (ADR-0017 decision 9).
            Aal::Two => latest_of(
                factors,
                &[FactorKind::Totp, FactorKind::Webauthn, FactorKind::External],
                now,
            ),
            Aal::Three if aal3 => latest_of(factors, &[FactorKind::Webauthn], now),
            Aal::Three => None,
            _ => (auth_time <= now).then_some(auth_time),
        };
        // The stored level a rule needs: AAL 3 is a qualified AAL 2 session.
        let stored = if rule.aal == Aal::One {
            Aal::One
        } else {
            Aal::Two
        };
        let insufficient_evidence =
            satisfied_at.is_none_or(|at| rule.max_age.is_some_and(|m| now.since(at) > m));
        if handle_aal < stored || insufficient_evidence {
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
            evaluate(&rules, "/public", Aal::One, false, t0, &factors, now),
            StepUpVerdict::NotRequired
        );
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::One, false, t0, &factors, now),
            StepUpVerdict::Required { aal: Aal::Two, .. }
        ));
        assert_eq!(
            evaluate(&rules, "/admin/x", Aal::Two, false, t0, &factors, now),
            StepUpVerdict::NotRequired
        );
        let later = t0.add(Duration::from_secs(601));
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::Two, false, t0, &factors, later),
            StepUpVerdict::Required { .. }
        ));
        assert!(forces_no_store(&rules));
        assert!(!forces_no_store(&[]));
    }

    #[test]
    fn aal3_rules_need_evidence_a_fresh_passkey_and_an_aal2_handle() {
        let rules = [rule(Some("/vault"), Aal::Three, Some(600))];
        let t0 = Timestamp(1_000_000);
        let now = t0.add(Duration::from_secs(60));
        let passkey = FactorEntry {
            kind: FactorKind::Webauthn,
            provider: None,
            at: t0,
        };
        let totp = FactorEntry {
            kind: FactorKind::Totp,
            provider: None,
            at: now,
        };
        let req =
            |aal, aal3, f: &[FactorEntry], at| evaluate(&rules, "/vault/x", aal, aal3, t0, f, at);
        assert_eq!(
            req(Aal::Two, true, std::slice::from_ref(&passkey), now),
            StepUpVerdict::NotRequired
        );
        // No evidence (a TOTP elevation, a synced passkey): required at AAL 3.
        assert!(matches!(
            req(Aal::Two, false, &[passkey.clone(), totp.clone()], now),
            StepUpVerdict::Required {
                aal: Aal::Three,
                ..
            }
        ));
        // A TOTP use never freshens an AAL 3 rule.
        assert!(matches!(
            req(Aal::Two, true, std::slice::from_ref(&totp), now),
            StepUpVerdict::Required { .. }
        ));
        // An AAL 1 handle is never enough, whatever the evidence says.
        assert!(matches!(
            req(Aal::One, true, std::slice::from_ref(&passkey), now),
            StepUpVerdict::Required { .. }
        ));
        // Stale passkey.
        assert!(matches!(
            req(Aal::Two, true, &[passkey], t0.add(Duration::from_secs(601))),
            StepUpVerdict::Required { .. }
        ));
        assert_eq!(required_level(&rules, "/vault/x"), Some(Aal::Three));
        assert_eq!(required_level(&rules, "/x"), None);
    }

    #[test]
    fn recovery_codes_never_satisfy_or_refresh_aal2() {
        let rules = [rule(Some("/admin"), Aal::Two, Some(600))];
        let t0 = Timestamp(1_000_000);
        let later = t0.add(Duration::from_secs(700));
        let webauthn = FactorEntry {
            kind: FactorKind::Webauthn,
            provider: None,
            at: t0,
        };
        let recovery = FactorEntry {
            kind: FactorKind::Recovery,
            provider: None,
            at: later,
        };
        // An old passkey plus a fresh recovery code: still stale.
        assert!(matches!(
            evaluate(
                &rules,
                "/admin/x",
                Aal::Two,
                false,
                t0,
                &[webauthn.clone(), recovery.clone()],
                later
            ),
            StepUpVerdict::Required { .. }
        ));
        // A recovery code alone: no AAL 2 evidence at all.
        assert!(matches!(
            evaluate(&rules, "/admin/x", Aal::Two, false, t0, &[recovery], later),
            StepUpVerdict::Required { .. }
        ));
        // A fresh passkey satisfies the rule.
        let fresh = FactorEntry {
            kind: FactorKind::Webauthn,
            provider: None,
            at: later,
        };
        assert_eq!(
            evaluate(
                &rules,
                "/admin/x",
                Aal::Two,
                false,
                t0,
                &[webauthn, fresh],
                later
            ),
            StepUpVerdict::NotRequired
        );
    }
}
