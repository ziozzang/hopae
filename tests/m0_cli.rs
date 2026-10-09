//! M0: command-line behavior of the `hopae` binary.
mod support;

use std::process::Command;
use support::*;

fn hopae() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hopae"));
    c.env_remove("HOPAE_CONFIG").env_remove(KEY_ENV);
    c
}

#[test]
fn version_prints_name_and_version() {
    let out = hopae().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("hopae {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn check_passes_with_valid_config_and_env() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &config_json(dir.path()));
    let out = hopae()
        .env(KEY_ENV, "super-secret-value")
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("super-secret-value"));
}

#[test]
fn check_fails_on_unknown_key() {
    let dir = tempfile::tempdir().unwrap();
    let json =
        config_json(dir.path()).replacen("\"state_dir\"", "\"bogus_key\": 1, \"state_dir\"", 1);
    let cfg = write_config(dir.path(), &json);
    let out = hopae()
        .env(KEY_ENV, "x")
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bogus_key"));
}

#[test]
fn check_fails_on_invalid_values_with_clear_messages() {
    let dir = tempfile::tempdir().unwrap();
    let json = config_json(dir.path())
        .replace("https://auth.example.test", "auth.example.test/x")
        .replace("127.0.0.1:0\", \"gateway\"", "nonsense\", \"gateway\"");
    let cfg = write_config(dir.path(), &json);
    let out = hopae()
        .env(KEY_ENV, "x")
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("listen.portal"), "{err}");
    assert!(err.contains("portal.public_url"), "{err}");
}

#[test]
fn check_fails_on_missing_env_and_names_only_the_variable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &config_json(dir.path()));
    for value in [None, Some("")] {
        let mut c = hopae();
        if let Some(v) = value {
            c.env(KEY_ENV, v);
        }
        let out = c.arg("--check").arg("--config").arg(&cfg).output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains(KEY_ENV));
    }
}

#[test]
fn check_requires_caller_key_env_unless_unauthenticated_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let json = config_json(dir.path()).replace(&format!(", \"caller_key_env\": \"{KEY_ENV}\""), "");
    let cfg = write_config(dir.path(), &json);
    let out = hopae()
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("caller_key_env"));

    let json = json.replace(
        "\"kind\": \"hangang\"",
        "\"kind\": \"hangang\", \"allow_unauthenticated_caller\": true",
    );
    let cfg = write_config(dir.path(), &json);
    let out = hopae()
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("development only"));
}

#[test]
fn missing_config_is_an_error() {
    let out = hopae().arg("--check").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = hopae()
        .arg("--check")
        .arg("--config")
        .arg("/nonexistent/hopae.json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}
