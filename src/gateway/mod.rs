//! Gateway adapter layer (M1). The only place that may name a gateway's wire
//! form: header names, status codes and cookie attributes (ADR-0013).
//! `hangang` will implement contract v1; a generic forward-auth adapter is later.
//!
//! In M0 the adapter only provides a deliberate fail-closed stub for the verify
//! route, so that a misrouted gateway is denied rather than allowed.

pub mod hangang;
