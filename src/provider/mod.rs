//! The provider abstraction and its implementations.
//! `types` is frozen (W0); `oidc` is the generic OpenID Connect client,
//! `presets` the built-in defaults, `registry` the configured set.

pub mod credentials;
pub mod ldap;
pub mod oidc;
pub mod presets;
pub mod registry;
pub mod types;

pub use registry::{Registry, apply_stored_reauth};
pub use types::*;
