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
    #[path = "s015_app_host_entry_points.rs"]
    mod s015_app_host_entry_points;
    #[path = "s016_native.rs"]
    mod s016_native;
    #[path = "s300_admin_access.rs"]
    mod s300_admin_access;
    #[path = "s301_admin_users.rs"]
    mod s301_admin_users;
    #[path = "s302_admin_sessions.rs"]
    mod s302_admin_sessions;
    #[path = "s303_admin_events.rs"]
    mod s303_admin_events;
    #[path = "s304_admin_status.rs"]
    mod s304_admin_status;
    #[path = "s305_admin_grants.rs"]
    mod s305_admin_grants;
    #[path = "s306_delegation.rs"]
    mod s306_delegation;
    #[path = "s307_subject_directory.rs"]
    mod s307_subject_directory;
    #[path = "s308_subject_lifecycle.rs"]
    mod s308_subject_lifecycle;
    #[path = "s309_authentication_explain.rs"]
    mod s309_authentication_explain;
    #[path = "s310_groups.rs"]
    mod s310_groups;
    #[path = "s314_admin_api_gaps.rs"]
    mod s314_admin_api_gaps;
    #[path = "s318_service_credentials.rs"]
    mod s318_service_credentials;
    #[path = "s319_config_authoritative_profiles.rs"]
    mod s319_config_authoritative_profiles;
    #[path = "s480_passkeys.rs"]
    mod s480_passkeys;
    #[path = "s900_kubernetes_workload.rs"]
    mod s900_kubernetes_workload;
}
