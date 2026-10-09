//! Application policy, binding, step-up rules. W0 provides the shared types;
//! the evaluators live in the submodules.

pub mod apps;
pub mod binding;
pub mod step_up;
pub mod types;

/// The handle and session lifetime state machine (ADR-0007). The
/// implementation lives next to the verify engine that drives it; it is
/// re-exported here under the name the shared-core contract gives it.
pub mod lifetimes {
    pub use crate::verify::lifetimes::*;
}

pub use types::*;
