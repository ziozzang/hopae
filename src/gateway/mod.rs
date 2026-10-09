//! Gateway adapter layer (M1). The only place that may name a gateway's wire
//! form: header names, status codes and cookie attributes (ADR-0013).
//! `hangang` implements contract v1; a generic forward-auth adapter is later.

pub mod canonical;
pub mod hangang;
pub mod recognition;
