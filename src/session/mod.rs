//! Sessions, handles, transactions, handoff codes and lifetimes.
//! W0 provides the shared types; the service (W1-D) is split by flow:
//! `service` (login round trip, callback, single sign-on, logout),
//! `transactions` (eviction room, the portal retry), `handoff` (minting
//! codes) and `switch` (the account switch). Redemption, recovery and the
//! unauthenticated `302` belong to `crate::verify` alone (ruling R-1).

pub mod handoff;
pub mod service;
pub mod switch;
pub mod transactions;
pub mod types;

pub use handoff::{MintRequest, MintedHandoff, append_handoff_param};
pub use service::{
    CallbackOutcome, Deps, IssuedHandle, LoginEntry, LogoutOutcome, ProviderChoice, ProviderLookup,
    RequestCtx, Service, ServiceConfig, SessionError,
};
pub use switch::{AccountSummary, SwitchChoice, SwitchOutcome, SwitchView};
pub use transactions::RetryOutcome;
pub use types::*;
