//! The verify decision engine (ADR-0013): a pure function of a
//! gateway-neutral [`VerifyInput`] and the stores, returning a [`Decision`].
//! No header, status or cookie attribute appears here; the gateway adapter
//! parses the request and renders the decision.

mod engine;
pub mod handoff;
pub(crate) mod human;
pub mod lifetimes;
pub mod operator;
pub mod types;

pub use types::*;

/// Return-target validation (ADR-0004), re-exported under the name the
/// shared-core contract gives it: `validate(url, snapshot, secure)`.
pub mod return_target {
    pub use crate::policy::apps::{MAX_URL_BYTES, validate_return_target as validate};
}

/// Decide one verify request.
///
/// Order: contract checks, return-target validation (host allowlist), the
/// reserved handoff parameter and redemption, handle lookup, lifetimes,
/// binding policy, user status and `authz_version`, application policy,
/// step-up rules (`no-store` only in M1), identity and cacheability. The
/// caller key, header parsing and canonical-path computation belong to the
/// adapter. Every store failure is `Deny{Unavailable}` (fail closed); the
/// request's budget (`ctx.deadline`, else now + `limits.budget`) is enforced
/// here and exhaustion answers `Deny{Unavailable, budget_exceeded}`.
pub async fn decide(ctx: &VerifyContext, input: VerifyInput) -> Decision {
    engine::run(ctx, input).await.0
}

/// As [`decide`], also returning why a presented handle was refused, when one
/// was (`unknown_handle`, `idle`, ...). A request that is answered with a
/// login redirect or, after that, with a rate-limit denial is recorded under
/// this reason (`verify.denied`, ADR-0009), so a flood of the same bad handle
/// is one counted series whatever the status each answer takes.
pub async fn decide_with_cause(
    ctx: &VerifyContext,
    input: VerifyInput,
) -> (Decision, Option<crate::event::types::Reason>) {
    engine::run(ctx, input).await
}

/// Owning native ingress only; no public Human constructor or wire activation.
pub(crate) async fn decide_for_human(
    ctx: &VerifyContext,
    input: &VerifyInput,
    owner: std::sync::Arc<human::Owner>,
    admission: human::Admission,
) -> (
    Decision,
    Option<crate::event::types::Reason>,
    Option<human::Witness>,
) {
    let ctx = match owner.native_context(ctx) {
        Ok(ctx) => ctx,
        Err(_) => {
            return (
                Decision::Deny {
                    reason: crate::event::types::reasons::STORE_UNAVAILABLE,
                    kind: DenyKind::Unavailable {
                        retry_after: std::time::Duration::from_secs(1),
                    },
                },
                None,
                None,
            );
        }
    };
    engine::run_for_human(&ctx, input, owner, admission).await
}
#[cfg(test)]
mod human_tests;
