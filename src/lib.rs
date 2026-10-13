//! Hopae: a single-binary identity provider that answers a gateway's
//! forward-authentication check. The crate is a library plus one binary;
//! the library exists so integration tests can start the listeners in-process.
//!
//! Milestone M0 provided the foundation (configuration, the two listeners,
//! the SQLite store, telemetry). The M1 shared core (identifiers, policy,
//! events, store traits, test hooks) is frozen by W0; the remaining modules
//! are filled by the M1 work packages.

/// String newtype with transparent serde, `new`, `as_str` and `Display`.
macro_rules! string_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(
            Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

pub mod admin;
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

pub mod auth_gateway;
