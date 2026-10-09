//! Scenario tests (`tests/scenarios/sNNN_*.rs`). W0 pre-declares every
//! scenario file with an empty placeholder module so the M1 work packages only
//! add test functions to their own files; this entry file is not edited again.
//!
//! Gateway-layer cases are `#[ignore]`d and carry `gateway` in their name so
//! that `make e2e` (`cargo test --test scenarios -- --ignored gateway`) runs
//! exactly them.
mod support;

#[path = "support/smoke.rs"]
mod smoke;

mod scenarios {
    #[path = "s001_unauthenticated_redirect.rs"]
    mod s001_unauthenticated_redirect;
    #[path = "s002_oidc_login.rs"]
    mod s002_oidc_login;
    #[path = "s003_handoff.rs"]
    mod s003_handoff;
    #[path = "s004_verify.rs"]
    mod s004_verify;
    #[path = "s005_return_target.rs"]
    mod s005_return_target;
    #[path = "s006_logout.rs"]
    mod s006_logout;
    #[path = "s007_header_contract.rs"]
    mod s007_header_contract;
    #[path = "s008_path_scope.rs"]
    mod s008_path_scope;
    #[path = "s009_cookies.rs"]
    mod s009_cookies;
    #[path = "s010_lifetimes.rs"]
    mod s010_lifetimes;
    #[path = "s011_ip_binding.rs"]
    mod s011_ip_binding;
    #[path = "s012_provider_failures.rs"]
    mod s012_provider_failures;
    #[path = "s013_preflight.rs"]
    mod s013_preflight;
    #[path = "s014_events.rs"]
    mod s014_events;
}
