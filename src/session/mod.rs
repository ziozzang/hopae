//! Sessions, handles, transactions, handoff codes and lifetimes.
//! W0 provides the shared types; the service (W1-D) is split by flow:
//! `service` (login round trip, callback, single sign-on, logout),
//! `transactions` (creating login transactions, the portal retry),
//! `handoff` (minting and redeeming codes) and `switch` (the account switch).

pub mod handoff;
pub mod service;
pub mod switch;
pub mod transactions;
pub mod types;

pub use handoff::{
    CodeDirectory, MintRequest, MintedHandoff, RedeemInput, RedeemResult, append_handoff_param,
};
pub use service::{
    CallbackOutcome, Deps, IssuedHandle, LoginEntry, LogoutOutcome, ProviderChoice, ProviderLookup,
    RequestCtx, Service, ServiceConfig, SessionError,
};
pub use switch::{AccountSummary, SwitchChoice, SwitchOutcome, SwitchView};
pub use transactions::{RetryOutcome, StartedLogin};
pub use types::*;
