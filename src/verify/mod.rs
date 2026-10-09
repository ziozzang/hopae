//! The verify decision engine (ADR-0013): a pure function of a
//! gateway-neutral [`VerifyInput`] and the stores, returning a [`Decision`].
//! No header, status or cookie attribute appears here; the gateway adapter
//! parses the request and renders the decision.

mod engine;
pub mod handoff;
pub mod lifetimes;
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
    engine::run(ctx, input).await
}
