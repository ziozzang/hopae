//! The provider abstraction and its implementations.
//! `types` is frozen (W0); `oidc` is the generic OpenID Connect client,
//! `presets` the built-in defaults, `registry` the configured set.

pub mod oidc;
pub mod presets;
pub mod registry;
pub mod types;

pub use registry::Registry;
pub use types::*;
