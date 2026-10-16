//! Scenario 008: path-scoped protection through gateway routes. Every case
//! runs through the real gateway binary (`HOPAE_E2E_GATEWAY_BINARY`,
//! `make e2e`) with the two-route fragment of the contract page; without the
//! variable it skips.
#![allow(unused_imports)]
use serde_json::json;

use crate::support::gateway::*;
use crate::support::*;

mod gateway_layer {
    use super::*;

    fn scoped(test: &str) -> Option<Stack> {
        Stack::with_routes(
            test,
            GatewayRoutes::new()
                .path_scoped(APP_HOST, "/admin")
                // The contract's third route: every handoff is delivered to
                // /_hopae/login (ADR-0015), which Hopae must answer.
                .hopae_prefix(APP_HOST)
                .portal(PORTAL_HOST),
        )
    }

    fn identity_names(r: &RecordedRequest) -> Vec<&str> {
        IDENTITY_HEADERS
            .iter()
            .copied()
            .filter(|n| r.header(n).is_some())
            .collect()
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_1_public_prefix_no_session() {
        let Some(s) = scoped("s008_1") else {
            return;
        };
        let b = s.gw.browser();
        for path in ["/", "/admin-tools/x"] {
            let r = b.get(&s.app, path);
            assert_eq!(r.status, 200, "{path}: {r:?}");
            assert_eq!(r.body, format!("echo {path}\n"));
        }
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 2, "both reached the upstream");
        for r in &seen {
            assert!(identity_names(r).is_empty(), "identity headers on {r:?}");
        }
        assert!(
            s.gw.tap.calls().is_empty(),
            "no verify call on the public route (/admin-tools is not a segment match)"
        );
        assert_eq!(txn_count(&s.hopae), 0, "no transaction created");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_2_protected_prefix_redirects() {
        let Some(s) = scoped("s008_2") else {
            return;
        };
        let b = s.gw.browser();
        for path in ["/admin", "/admin/x"] {
            let r = b.get(&s.app, path);
            assert_eq!(r.status, 302, "{path}: {r:?}");
            let loc = r.location().unwrap();
            assert!(
                loc.starts_with("https://auth.example.test/login?txn="),
                "{loc}"
            );
            assert_eq!(
                return_target(&s.hopae, &txn_of(&r)).as_deref(),
                Some(format!("https://app.example.test{path}").as_str())
            );
        }
        assert!(s.echo.requests().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_3_handoff_on_protected_prefix() {
        let Some(s) = scoped("s008_3") else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, &s.app, "/admin/x");
        assert!(
            l.handoff_location.contains("_hopae_handoff="),
            "{}",
            l.handoff_location
        );
        // The verify call consumed the code and planted the cookie, Path=/.
        assert_eq!(l.handoff.status, 302, "{:?}", l.handoff);
        assert_eq!(
            l.handoff.location(),
            Some("https://app.example.test/admin/x"),
            "the clean URL"
        );
        let planted = l
            .handoff
            .set_cookies()
            .into_iter()
            .find(|c| c.starts_with("__Host-hopae="))
            .expect("handle cookie planted")
            .to_string();
        assert!(
            planted.contains("; Path=/;") || planted.ends_with("; Path=/"),
            "{planted}"
        );
        assert!(
            s.echo.requests().is_empty(),
            "the upstream never saw the handoff navigation"
        );
        let r = b.follow(&s.app, &l.handoff);
        assert_eq!(r.status, 200, "{r:?}");
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path(), "/admin/x");
        assert!(!seen[0].raw_path.contains("_hopae_handoff"));
        assert!(
            seen[0].header("x-forwarded-user").is_some(),
            "identity headers present"
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_4_cookie_unused_on_public_paths() {
        let Some(s) = scoped("s008_4") else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, &s.app, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        let handle = b
            .jar
            .for_host(&s.app)
            .value("__Host-hopae")
            .expect("cookie planted");
        s.gw.tap.clear();
        s.echo.clear();
        let r = b.get(&s.app, "/");
        assert_eq!(r.status, 200, "{r:?}");
        assert!(
            s.gw.tap.calls().is_empty(),
            "the public route does not call Hopae"
        );
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0]
                .header("cookie")
                .is_some_and(|c| c.contains(&format!("__Host-hopae={handle}"))),
            "the application receives the cookie header"
        );
        assert!(identity_names(&seen[0]).is_empty(), "no identity headers");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_5_preflight_reports_missing_route() {
        // `other.example.org` is registered in Hopae and has no route on the gateway.
        let Some(s) = Stack::start(
            "s008_5",
            Fixture::new("m1-two-domains"),
            GatewayRoutes::new()
                .path_scoped(APP_HOST, "/admin")
                .portal(PORTAL_HOST),
            Edge::Terminator,
        ) else {
            return;
        };
        let routes = s.gw.admin_routes();
        assert_eq!(
            routes.status, 200,
            "the gateway's read-only route listing: {routes:?}"
        );

        let dir = tempfile::tempdir().expect("dir");
        let mut cfg = s.hopae.config().clone();
        cfg["state_dir"] = json!(dir.path().join("state"));
        cfg["gateway"]["admin_url"] = json!(format!("http://{}", s.gw.admin));
        cfg["gateway"]["readonly_token_env"] = json!("HOPAE_TEST_GW_READONLY");
        let path = dir.path().join("hopae.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let run = |extra: &[&str]| {
            let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_hopae"));
            c.arg("--check").args(extra).arg("--config").arg(&path);
            c.env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env(KEY_ENV, s.hopae.env_value(KEY_ENV).unwrap())
                .env("HOPAE_TEST_MOCK_SECRET", "mock-secret-for-check")
                .env("HOPAE_TEST_GW_READONLY", s.gw.admin_token());
            let o = c.output().expect("run hopae --check");
            (
                o.status.code(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            )
        };
        let (code, out) = run(&[]);
        assert_eq!(code, Some(0), "a warning, not an error: {out}");
        assert!(
            out.contains(
                "app other: no gateway route with auth.url pointing at this instance for host other.example.org"
            ),
            "{out}"
        );
        assert!(
            !out.contains("for host app.example.test"),
            "the host that has a protected route is not reported: {out}"
        );
        assert!(
            !out.contains(s.gw.admin_token()),
            "the token is never printed"
        );
        let (code, out) = run(&["--strict"]);
        assert_eq!(code, Some(2), "{out}");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_6_fragment_validation() {
        let Some(s) = scoped("s008_6") else {
            return;
        };
        // Hangang's own validation accepts both fragments of the contract page ...
        let (ok, out) = s.gw.check();
        assert!(ok, "the path-scoped pair + portal: {out}");
        let (ok, out) = s.gw.check_variant(|doc| {
            doc["http"] = json!([{
                "id": "app-example", "access_mode": "protected", "host": APP_HOST,
                "path_prefix": "/", "backends": ["http://127.0.0.1:9"],
                "auth": auth_fragment("http://127.0.0.1:9/_hopae/verify"),
            }]);
        });
        assert!(ok, "the whole-host fragment: {out}");
        // ... and a fragment with forward_response: false is accepted by the gateway.
        // (Hopae's drift check flagging it as forward_response_disabled is phase 1, M2.)
        let (ok, out) = s.gw.check_variant(|doc| {
            for r in doc["http"].as_array_mut().unwrap() {
                if r.get("auth").is_some() {
                    r["auth"]["forward_response"] = json!(false);
                }
            }
        });
        assert!(ok, "forward_response=false: {out}");
        // The gateway rejects what is not in the fragment's vocabulary: an
        // unknown key in static_request_headers' value, and a reserved name.
        let (ok, out) = s.gw.check_variant(|doc| {
            for r in doc["http"].as_array_mut().unwrap() {
                if r.get("auth").is_some() {
                    r["auth"]["static_request_headers"]["x-original-url"] = json!("x");
                }
            }
        });
        assert!(!ok, "a reserved static header must be refused: {out}");
        // The route table the gateway serves lists the protected route with its auth block.
        let listing = s.gw.admin_routes();
        assert_eq!(listing.status, 200);
        assert!(listing.body.contains("site-admin"), "{:.300}", listing.body);
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_a1_path_tricks_do_not_escape() {
        let Some(s) = scoped("s008_a1") else {
            return;
        };
        let b = s.gw.browser();
        // The outcome per form is the gateway's behavior, recorded here as the
        // scenario asks: (path, status, path the upstream saw or None).
        // HC-10: a gateway that knows the route field `path_case` matches protected
        // prefixes case-insensitively, so `/ADMIN/x` reaches the external check.
        // Probe the binary with its own `--check`, so the same test stays right
        // before and after the gateway gains the field.
        let (base_ok, base_out) = s.gw.check_variant(|_| {});
        assert!(
            base_ok,
            "the unmodified configuration must check: {base_out}"
        );
        let (hc10, _) = s.gw.check_variant(|doc| {
            fn mark(v: &mut serde_json::Value) {
                match v {
                    serde_json::Value::Object(o) => {
                        if o.get("id")
                            .and_then(|i| i.as_str())
                            .is_some_and(|i| i.starts_with("site-admin"))
                        {
                            o.insert("path_case".into(), serde_json::json!("insensitive"));
                        }
                        o.values_mut().for_each(mark);
                    }
                    serde_json::Value::Array(a) => a.iter_mut().for_each(mark),
                    _ => {}
                }
            }
            mark(doc);
        });
        let upper: (u16, Option<&str>) = if hc10 {
            (302, None)
        } else {
            (200, Some("/ADMIN/x"))
        };
        let recorded: [(&str, u16, Option<&str>); 4] = [
            // an encoded slash is refused by the gateway's path validation
            ("/admin%2Fx", 400, None),
            // route matching is case-sensitive: this is the PUBLIC route, so the
            // request reaches the upstream as /ADMIN/x, a different resource for a
            // case-sensitive upstream (see the report: a case-insensitive upstream
            // would serve /admin content here)
            ("/ADMIN/x", upper.0, upper.1),
            // dot segments are refused (the gateway's default; allow_dot_segments is off)
            ("/admin/../admin/x", 400, None),
            // an empty segment is refused
            ("//admin/x", 400, None),
        ];
        for (path, status, upstream) in recorded {
            s.echo.clear();
            s.gw.tap.clear();
            let r = b.get(&s.app, path);
            let reached: Vec<String> = s
                .echo
                .requests()
                .iter()
                .map(|q| q.decoded_path.clone())
                .collect();
            assert_eq!(r.status, status, "{path}: {r:?}");
            assert_eq!(
                reached,
                upstream.map(String::from).into_iter().collect::<Vec<_>>(),
                "{path}"
            );
            // The invariant of the scenario for a case-sensitive upstream: nothing
            // reached the upstream under /admin without a session.
            for p in &reached {
                assert!(
                    p != "/admin" && !p.starts_with("/admin/"),
                    "{path} reached the upstream as {p} without a session"
                );
            }
        }
        // And the exact form is protected: 302, no upstream request.
        s.echo.clear();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 302);
        assert!(s.echo.requests().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_a2_identity_headers_stripped_on_public_route() {
        let Some(s) = scoped("s008_a2") else {
            return;
        };
        let b = s.gw.browser();
        let extra: Vec<(&str, &str)> = IDENTITY_HEADERS.iter().map(|n| (*n, "admin")).collect();
        let r = b.get_with(&s.app, "/", &extra);
        assert_eq!(r.status, 200, "{r:?}");
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            identity_names(&seen[0]).is_empty(),
            "gateway-wide stripping of the declared names: {:?}",
            identity_names(&seen[0])
        );
        assert!(s.gw.tap.calls().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_a3_host_header_games() {
        // The gateway is the edge: it regenerates x-forwarded-host from the Host it routed on.
        let Some(s) = Stack::direct(
            "s008_a3",
            GatewayRoutes::new()
                .path_scoped(APP_HOST, "/admin")
                .portal(PORTAL_HOST),
        ) else {
            return;
        };
        let b = s.gw.browser();
        let r = b.get_with(
            &s.app,
            "/admin/x",
            &[("x-forwarded-host", "other.example.org")],
        );
        assert_eq!(r.status, 302, "{r:?}");
        let calls = s.gw.tap.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].header("x-forwarded-host"),
            Some(s.app.as_str()),
            "regenerated from Host"
        );
        let ou = calls[0].header("x-original-url").expect("x-original-url");
        assert!(ou.starts_with(&format!("http://{}/admin/x", s.app)), "{ou}");
        assert!(!ou.contains("other.example.org"));
        assert_eq!(
            return_target(&s.hopae, &txn_of(&r)).as_deref(),
            Some(format!("http://{}/admin/x", s.app).as_str()),
            "the transaction targets the routed host"
        );
        assert!(!r.location().unwrap().contains("other.example.org"));
        assert!(s.echo.requests().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_a4_route_without_protected_mode_flagged() {
        let Some(s) = Stack::with_routes(
            "s008_a4",
            GatewayRoutes::new()
                .path_scoped(APP_HOST, "/admin")
                .portal(PORTAL_HOST)
                .mutate(|routes| {
                    for r in routes.iter_mut() {
                        if r.get("auth").is_some() {
                            r["access_mode"] = json!("legacy");
                        }
                    }
                }),
        ) else {
            return;
        };
        // Accepted by the gateway, and verify behaves identically.
        let (ok, out) = s.gw.check();
        assert!(ok, "{out}");
        let b = s.gw.browser();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 302, "the gateway still calls auth: {r:?}");
        assert_eq!(s.gw.tap.calls().len(), 1);
        assert!(s.echo.requests().is_empty());
        // The documented invariant is `protected`; the drift check that flags
        // `access_mode_not_protected` is phase 1 (M2), not implemented in M1.
        let listing = s.gw.admin_routes();
        assert!(listing.body.contains("legacy") || !listing.body.contains("\"protected\""));
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s008_a5_percent_encoded_prefix_canonicalized() {
        let Some(s) = scoped("s008_a5") else {
            return;
        };
        // Unit half: the canonical path and the enforced step-up rule.
        let canon = hopae::gateway::canonical::canonical_path("/%61dmin/x").expect("canonical");
        assert_eq!(canon.as_str(), "/admin/x");
        let rule = hopae::policy::types::StepUpRule {
            path_prefix: Some("/admin".into()),
            aal: hopae::session::Aal::Two,
            max_age: None,
            factor: None,
            enrollment_grace: false,
        };
        assert!(hopae::policy::step_up::rule_matches(&rule, canon.as_str()));
        assert!(matches!(
            hopae::policy::step_up::evaluate(
                &[rule],
                canon.as_str(),
                hopae::session::Aal::One,
                false,
                hopae::crypto::Timestamp(0),
                &[],
                hopae::crypto::Timestamp(1000),
            ),
            hopae::policy::step_up::StepUpVerdict::Required { .. }
        ));

        // Gateway half. Without a cookie: site-admin is selected from the
        // canonical path, Hopae sees the raw x-original-url, 302, no upstream request.
        let b = s.gw.browser();
        let r = b.get(&s.app, "/%61dmin/x");
        assert_eq!(r.status, 302, "{r:?}");
        let calls = s.gw.tap.calls();
        assert_eq!(calls.len(), 1, "the protected route called Hopae");
        let ou = calls[0].header("x-original-url").expect("x-original-url");
        assert!(ou.ends_with("/%61dmin/x"), "raw path preserved: {ou}");
        assert!(
            s.echo.requests().is_empty(),
            "no upstream request without a session"
        );

        // With a session (login for /admin/x first): allowed, and the decoding
        // upstream sees /admin/x.
        let l = b.login(&s.idp, &s.app, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        s.echo.clear();
        s.gw.tap.clear();
        let r = b.get(&s.app, "/%61dmin/x");
        assert_eq!(r.status, 200, "{r:?}");
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].decoded_path, "/admin/x");
        assert!(seen[0].header("x-forwarded-user").is_some());

        // HC-6 is not in this gateway build, so the canonical-path agreement is
        // exercised by injecting the header on the verify call: a mismatch is denied.
        s.gw.tap.set_mods(TapMods {
            request_headers: vec![("x-hangang-canonical-path".into(), "/other".into())],
            ..TapMods::default()
        });
        s.echo.clear();
        let r = b.get(&s.app, "/%61dmin/x");
        s.gw.tap.reset_mods();
        assert_ne!(r.status, 200, "{r:?}");
        assert!(s.echo.requests().is_empty(), "denied before the upstream");
        let denied = s.hopae.hooks.events(Some("verify.denied"), None);
        let _ = denied;

        // Non-canonical inputs are denied by Hopae (or earlier by the gateway):
        // verify directly with the raw URL, as the gateway would send it.
        let h = b
            .jar
            .for_host(&s.app)
            .value("__Host-hopae")
            .expect("handle");
        for path in ["/admin/%2e%2e/x", "/admin//x", "/%2561dmin/x"] {
            let r = s.hopae.verify(
                VerifyRequest::document(&format!("https://app.example.test{path}"))
                    .ip("192.0.2.10")
                    .cookie("__Host-hopae", &h),
            );
            assert_eq!(r.status, 403, "{path}: {r:?}");
            assert_eq!(
                r.header("x-hopae-reason"),
                Some("path_not_canonical"),
                "{path}"
            );
            // ... and through the gateway nothing reaches the upstream either.
            s.echo.clear();
            let g = b.get(&s.app, path);
            assert_ne!(g.status, 200, "{path}: {g:?}");
            assert!(s.echo.requests().is_empty(), "{path} reached the upstream");
        }
    }
}
