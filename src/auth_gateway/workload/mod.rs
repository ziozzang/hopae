//! Kubernetes workload identity (Hangang ADR 0022 Decision 5, P0).
//!
//! `kubernetes_workload` verifies projected ServiceAccount tokens **offline**
//! against the issuer's OIDC discovery/JWKS (pinned issuer and CA, bounded
//! key cache with rotation, rate-limited `kid`-miss refetch), checks the
//! required audience, `exp`/`nbf`/`iat` with bounded skew, the token lifetime
//! and the `kubernetes.io` bound-object claims, and keeps a short positive
//! cache. No API-server request is made on the hot path; revocation is an
//! optional watch-backed index with bounded staleness. The principal is the
//! ServiceAccount (`wk2:`, SPIFFE ID), never the Pod.
//!
//! The older `kubernetes_tokenreview` connector remains as a deprecated
//! fallback (off by default).
pub mod cache;
pub mod events;
pub mod http;
pub mod identity;
pub mod keys;
pub mod metrics;
pub mod revocation;
pub mod signals;
pub mod verify;

pub use identity::{SubjectMode, WorkloadAttributes};
pub use verify::{Connector, Profile};

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
