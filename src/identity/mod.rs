//! Users, identities, linking policy and the identity service (ADR-0011).
//! W0 provides the shared types; the service is W1-D.

pub mod email;
pub mod linking;
pub mod service;
pub mod types;

pub use service::{Resolution, Service};
pub use types::*;
