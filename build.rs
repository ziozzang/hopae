// Re-run the build when an embedded migration changes (include_str! tracks the
// files itself; this also catches added files in the directory).
fn main() {
    let profile = std::env::var("PROFILE").expect("Cargo build profile is required");
    let test_hooks = std::env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some();
    validate_release_features(&profile, test_hooks);
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_HOOKS");
    println!("cargo:rerun-if-changed=src/store/migrations");
}

fn validate_release_features(profile: &str, test_hooks: bool) {
    assert!(
        profile != "release" || !test_hooks,
        "Hopae release builds must not enable test-hooks; omit --all-features"
    );
}

#[cfg(test)]
mod tests {
    use super::validate_release_features;

    #[test]
    fn release_refuses_test_control_surfaces() {
        assert!(std::panic::catch_unwind(|| validate_release_features("release", true)).is_err());
    }

    #[test]
    fn production_release_and_debug_fixtures_remain_supported() {
        validate_release_features("release", false);
        validate_release_features("debug", true);
        validate_release_features("debug", false);
    }
}
