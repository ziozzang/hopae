//! Hopae: a single-binary identity provider that answers a gateway's
//! forward-authentication check. The crate is a library plus one binary;
//! the library exists so integration tests can start the listeners in-process.
//!
//! Milestone M0 provides only the foundation: configuration, the two
//! listeners with their fixed routes, the SQLite store with migrations and
//! telemetry. Every other module is a documented placeholder for later work.

pub mod app;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod event;
pub mod factor;
pub mod gateway;
pub mod http;
pub mod identity;
pub mod lua;
pub mod policy;
pub mod portal;
pub mod provider;
pub mod session;
pub mod store;
pub mod telemetry;
pub mod update;
pub mod verify;
