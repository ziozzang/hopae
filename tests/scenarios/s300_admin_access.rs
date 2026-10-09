//! Placeholder declared by W0 (M4-min): the scenario tests of this file are
//! added by their work package (see `internal/M4MIN_PLAN.md`).

// ---- 300-8 (W1-C): preflight --------------------------------------------------

mod s300_8 {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use serde_json::{Value, json};

    use crate::support::*;

    fn render(dir: &Path, fixture: &'static str, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let idp = MockIdp::start("default");
        let mut v = Fixture::new(fixture).render(dir, &idp);
        edit(&mut v);
        let p = dir.join(format!("{fixture}.json"));
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        p
    }

    struct Out {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    impl Out {
        fn all(&self) -> String {
            format!("{:?}\n{}\n{}", self.code, self.stdout, self.stderr)
        }
    }

    fn check(cfg: &Path, extra: &[&str]) -> Out {
        let o = Command::new(env!("CARGO_BIN_EXE_hopae"))
            .arg("--check")
            .args(extra)
            .arg("--config")
            .arg(cfg)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOPAE_TEST_GATEWAY_KEY", "gwkey-value-0123456789")
            .env("HOPAE_TEST_MOCK_SECRET", "mock-secret-value-9876543210")
            .output()
            .unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn json_after(s: &str, marker: &str) -> Value {
        let at = s
            .find(marker)
            .unwrap_or_else(|| panic!("{marker:?} in:\n{s}"));
        let rest = &s[at..];
        let brace = rest.find('{').expect("json");
        serde_json::Deserializer::from_str(&rest[brace..])
            .into_iter::<Value>()
            .next()
            .unwrap()
            .expect("parses")
    }

    #[test]
    fn s300_8_preflight_prints_console_route_capabilities_and_refuses_reserved_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();

        // The base file: route fragment, implicit application, capability line.
        let cfg = render(d, "m4-admin", |_| {});
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        let frag = json_after(&o.stdout, "gateway route for the console host");
        assert_eq!(frag["id"], "hopae-admin", "{frag}");
        assert_eq!(frag["host"], "hopae-admin.example.test");
        assert!(
            frag["auth"]["url"]
                .as_str()
                .unwrap()
                .ends_with("/_hopae/verify")
        );
        assert_eq!(frag["auth"]["forward_response"], true);
        assert_eq!(
            frag["auth"]["static_request_headers"]["x-hopae-gateway-key"],
            json!({"env": "HANGANG_HOPAE_KEY"})
        );
        assert!(
            frag.get("strip_request_cookies").is_none()
                && frag["auth"].get("strip_request_cookies").is_none(),
            "the console needs its handle cookie: {frag}"
        );
        let app_line = o
            .stdout
            .lines()
            .find(|l| l.trim_start().starts_with("admin (enabled"))
            .unwrap_or_else(|| panic!("implicit application line:\n{}", o.stdout));
        for needle in [
            "hopae-admin.example.test",
            "implicit",
            "session idle 30m absolute 12h",
            "ip=strict",
            "max_auth_age 12h",
        ] {
            assert!(app_line.contains(needle), "{needle}: {app_line}");
        }
        assert!(
            o.stdout.contains("admin.untrusted_peers refuse"),
            "{}",
            o.stdout
        );
        assert!(
            o.stdout
                .contains("reauth max_age: console freshness is a provider-verified challenge"),
            "{}",
            o.stdout
        );
        assert!(o.stdout.trim_end().ends_with("config ok"), "{}", o.stdout);

        // The reserved application id.
        let cfg = render(d, "m4-admin", |v| {
            let app = v["apps"][0].clone();
            v["apps"] = json!([app, {"app_id": "admin", "display_name": "x"}]);
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(
            o.stderr.contains("apps[1].app_id") && o.stderr.contains("reserved"),
            "{}",
            o.all()
        );

        // require_aal: 2 warns; --strict refuses.
        let cfg = render(d, "m4-admin", |v| v["admin"]["require_aal"] = json!(2));
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        assert!(
            o.stderr.contains("admin.require_aal") && o.stderr.contains("will be refused"),
            "{}",
            o.all()
        );
        assert_eq!(check(&cfg, &["--strict"]).code, Some(2));

        // listeners must differ.
        let cfg = render(d, "m4-admin", |v| {
            v["listen"]["portal"] = json!("127.0.0.1:18700");
            v["listen"]["admin"] = json!("127.0.0.1:18700");
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("must differ"), "{}", o.all());

        // origin without path.
        let cfg = render(d, "m4-admin", |v| {
            v["admin"]["public_url"] = json!("https://hopae-admin.example.test/path")
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("origin without path"), "{}", o.all());

        // the console host is registered implicitly.
        let cfg = render(d, "m4-admin", |v| {
            v["apps"][0]["hosts"] = json!(["app.example.test", "hopae-admin.example.test"]);
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());
        assert!(o.stderr.contains("registered implicitly"), "{}", o.all());

        // untrusted_peers values.
        let cfg = render(d, "m4-admin", |v| {
            v["admin"]["untrusted_peers"] = json!("maybe")
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(2), "{}", o.all());

        // max_auth_age below the bound.
        for bad in ["60s", "29m"] {
            let cfg = render(d, "m4-admin", |v| v["admin"]["max_auth_age"] = json!(bad));
            let o = check(&cfg, &[]);
            assert_eq!(o.code, Some(2), "{bad}: {}", o.all());
            assert!(
                o.stderr.contains("admin.max_auth_age must be at least 30m"),
                "{bad}: {}",
                o.all()
            );
        }

        // A provider whose capability is unsupported (the google preset).
        let cfg = render(d, "m4-admin-unsupported", |v| {
            v["providers"].as_array_mut().unwrap().push(json!({
                "provider_id": "google",
                "kind": "oidc",
                "display_name": "Google",
                "client_id": "g-client",
                "client_secret_env": "HOPAE_TEST_MOCK_SECRET",
                "issuer": "https://accounts.google.com",
                "scope": "openid email profile"
            }));
        });
        let o = check(&cfg, &[]);
        assert_eq!(o.code, Some(0), "{}", o.all());
        assert!(
            o.stdout.contains(
                "reauth unsupported: console freshness is Hopae login age; enforce a second factor at the provider for administrators"
            ),
            "{}",
            o.all()
        );
    }
}
