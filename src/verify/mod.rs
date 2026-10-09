//! The verify decision engine. W0 provides the types and a fail-closed
//! placeholder `decide`; W1-A replaces the placeholder with the engine.

pub mod types;

pub use types::*;

/// Placeholder with the frozen signature: every call is denied as unavailable
/// (fail closed). W1-A replaces the body; the signature does not change.
pub async fn decide(_ctx: &VerifyContext, _input: VerifyInput) -> Decision {
    Decision::Deny {
        reason: crate::event::types::reasons::STORE_UNAVAILABLE,
        kind: DenyKind::Unavailable {
            retry_after: std::time::Duration::from_secs(1),
        },
    }
}
