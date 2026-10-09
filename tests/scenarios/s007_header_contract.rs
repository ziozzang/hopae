//! Scenario 007: identity headers reach the upstream only from Hopae; client
//! copies are stripped. Every case runs through the real gateway binary
//! (`HOPAE_E2E_GATEWAY_BINARY`, `make e2e`); without the variable it skips.
#![allow(unused_imports)]
use crate::support::gateway::*;
use crate::support::*;

fn handle(b: &Browser, host: &str) -> String {
    b.jar
        .for_host(host)
        .value("__Host-hopae")
        .expect("the browser holds the application handle")
}

/// The headers the identity set must contain at the upstream.
const SET: [&str; 9] = [
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-preferred-username",
    "x-hopae-session",
    "x-hopae-provider",
    "x-hopae-auth-time",
    "x-hopae-expires",
    "x-hopae-aal",
    "x-hopae-factors",
];

mod gateway_layer {
    use super::*;

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_1_upstream_receives_identity_set() {
        let Some(s) = Stack::basic("s007_1") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        s.echo.clear();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 200, "{r:?}");
        assert_eq!(
            r.body, "echo /admin/x\n",
            "the client response is the upstream's"
        );
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        for name in SET {
            assert!(seen[0].header(name).is_some(), "upstream saw no {name}");
        }
        assert!(
            seen[0]
                .header("x-forwarded-user")
                .unwrap()
                .starts_with("u_"),
            "the user id is Hopae's"
        );
        assert!(seen[0].header("x-hopae-reason").is_none());
        assert!(seen[0].header("x-hopae-contract").is_none());
        assert!(
            seen[0].header("x-hopae-gateway-key").is_none(),
            "the caller key never goes upstream"
        );
        // The client response carries none of the identity headers (they are request headers).
        for name in SET {
            assert!(r.header(name).is_none(), "client response leaked {name}");
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_2_unauthenticated_never_reaches_upstream() {
        let Some(s) = Stack::basic("s007_2") else {
            return;
        };
        let b = s.gw.browser();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 302, "{r:?}");
        assert!(
            r.location()
                .unwrap()
                .starts_with("https://auth.example.test/login?txn="),
            "{:?}",
            r.location()
        );
        assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
        assert!(
            s.echo.requests().is_empty(),
            "the upstream recorded a request"
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_3_gateway_configuration_validates() {
        let Some(s) = Stack::basic("s007_3") else {
            return;
        };
        let (ok, out) = s.gw.check();
        assert!(ok, "hangang --check rejected the contract fragment: {out}");
        let doc = s.gw.config();
        let mut protected = 0;
        for route in doc["http"].as_array().expect("routes") {
            if route["access_mode"] == "protected" {
                protected += 1;
                let declared: Vec<&str> = route["auth"]["response_headers"]
                    .as_array()
                    .expect("response_headers")
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                for name in IDENTITY_HEADERS {
                    assert!(
                        declared.contains(&name),
                        "{name} is not in response_headers"
                    );
                }
                assert_eq!(
                    route["auth"]["static_request_headers"]["x-hopae-gateway-key"]["env"],
                    GATEWAY_KEY_ENV
                );
            }
        }
        assert_eq!(protected, 1);
        // Everything identity-shaped that Hopae really emits on an allow is declared.
        let b = s.logged_in("/admin/x");
        let h = handle(&b, &s.app);
        let r = s.hopae.verify(
            VerifyRequest::document("https://app.example.test/admin/x")
                .ip("192.0.2.10")
                .cookie("__Host-hopae", &h),
        );
        assert_eq!(r.status, 200, "{r:?}");
        let declared: Vec<String> = IDENTITY_HEADERS.iter().map(|s| s.to_string()).collect();
        let not_identity = [
            "x-hopae-reason",
            "x-hopae-contract",
            "x-hopae-gen",
            "x-hopae-fresh-until",
        ];
        for (k, _) in &r.headers {
            if (k.starts_with("x-forwarded-") || k.starts_with("x-hopae-"))
                && !not_identity.contains(&k.as_str())
            {
                assert!(
                    declared.contains(k),
                    "Hopae emits {k}, the fragment does not relay it"
                );
            }
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_4_values_survive_gateway() {
        let Some(s) = Stack::basic("s007_4") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        let h = handle(&b, &s.app);
        let direct = s.hopae.verify(
            VerifyRequest::document("https://app.example.test/admin/x")
                .ip("192.0.2.10")
                .cookie("__Host-hopae", &h),
        );
        let emitted = direct
            .header("x-forwarded-preferred-username")
            .expect("Hopae emits the preferred username")
            .to_string();
        assert_eq!(
            emitted, "Alice%20%EA%B9%80",
            "percent-encoded, non-ASCII safe"
        );
        s.echo.clear();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 200, "{r:?}");
        let seen = s.echo.requests();
        assert_eq!(
            seen[0].header("x-forwarded-preferred-username"),
            Some(emitted.as_str()),
            "identical bytes at the upstream"
        );
        for name in ["x-forwarded-email", "x-hopae-session", "x-hopae-provider"] {
            assert_eq!(seen[0].header(name), direct.header(name), "{name}");
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_a1_client_identity_header_replaced() {
        let Some(s) = Stack::basic("s007_a1") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        s.echo.clear();
        let r = b.get_with(
            &s.app,
            "/admin/x",
            &[
                ("x-forwarded-user", "admin"),
                ("x-forwarded-groups", "root"),
            ],
        );
        assert_eq!(r.status, 200, "{r:?}");
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        let user = seen[0].header("x-forwarded-user").expect("identity user");
        assert!(
            user.starts_with("u_"),
            "Hopae's value, not the client's: {user}"
        );
        assert_ne!(user, "admin");
        assert!(
            seen[0].header("x-forwarded-groups").is_none(),
            "the client copy of a header Hopae did not emit is stripped"
        );
        let all: Vec<_> = seen[0]
            .headers
            .iter()
            .filter(|(k, _)| k == "x-forwarded-user")
            .collect();
        assert_eq!(all.len(), 1, "exactly one copy");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_a2_oversized_identity_refused() {
        let Some(s) = Stack::basic("s007_a2") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        s.echo.clear();
        // Hopae's own 4 KiB cap makes this unreachable in production (unit test on the
        // emitter); the tap makes the answer what a Hopae without the cap would send.
        s.gw.tap.set_mods(TapMods {
            response_headers: vec![("x-forwarded-groups".into(), "g".repeat(20 * 1024))],
            ..TapMods::default()
        });
        let r = b.get(&s.app, "/admin/x");
        s.gw.tap.reset_mods();
        assert_eq!(r.status, 503, "{r:?}");
        assert!(s.echo.requests().is_empty(), "the upstream saw the request");
        let ok = b.get(&s.app, "/admin/x");
        assert_eq!(ok.status, 200, "the cap is per answer, nothing is stuck");
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_a3_client_x_original_on_portal_route_ignored() {
        // The gateway is the edge here: no trusted proxy, so every x-forwarded-*
        // the portal sees is the gateway's.
        let Some(s) = Stack::direct("s007_a3", GatewayRoutes::standard()) else {
            return;
        };
        let evil = [
            ("x-forwarded-for", "203.0.113.9"),
            ("x-original-url", "https://evil.example.org/"),
            ("x-original-uri", "/evil"),
        ];
        let b = s.gw.browser().spoofing(&evil);
        s.hopae.hooks.counters(); // hooks reachable
        let l = b.login(&s.idp, &s.app, "/admin/x");

        let calls = s.gw.portal_tap.calls();
        assert!(!calls.is_empty(), "the portal route reached Hopae's portal");
        for c in &calls {
            assert_eq!(
                c.header("x-forwarded-for"),
                Some("127.0.0.1"),
                "the gateway regenerates x-forwarded-for from the connection, not the client: {c:?}"
            );
            assert_eq!(
                c.header("x-original-url"),
                Some("https://evil.example.org/"),
                "routes without external authorization leave x-original-* untouched: {c:?}"
            );
            assert_eq!(c.header("x-original-uri"), Some("/evil"), "{c:?}");
        }
        // The portal never read them: no Location names the attacker host and the
        // return target of the transaction is the application URL that started it.
        for hop in [
            &l.first,
            &l.portal_page,
            &l.provider_redirect,
            &l.callback,
            &l.handoff,
        ] {
            if let Some(loc) = hop.location() {
                assert!(!loc.contains("evil.example.org"), "{loc}");
            }
        }
        assert_eq!(
            l.handoff_location.split('?').next().unwrap(),
            format!("http://{}/admin/x", s.app),
            "return_target unchanged"
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_a4_unauthenticated_identity_headers_stripped() {
        let Some(s) = Stack::basic("s007_a4") else {
            return;
        };
        let b = s.gw.browser();
        let extra: Vec<(&str, &str)> = IDENTITY_HEADERS.iter().map(|n| (*n, "attacker")).collect();
        let r = b.get_with(&s.app, "/admin/x", &extra);
        assert_eq!(r.status, 302, "{r:?}");
        assert!(r.location().unwrap().contains("/login?txn="));
        assert!(s.echo.requests().is_empty(), "the upstream saw something");
        let calls = s.gw.tap.calls();
        assert_eq!(calls.len(), 1);
        for name in IDENTITY_HEADERS {
            assert!(
                calls[0].header(name).is_none(),
                "the verify call Hopae received contained {name}"
            );
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s007_a5_duplicate_cookie_fields_joined() {
        let Some(s) = Stack::basic("s007_a5") else {
            return;
        };
        let b = s.logged_in("/admin/x");
        let h = handle(&b, &s.app);
        s.gw.tap.clear();
        s.echo.clear();
        // HTTP/2 (prior knowledge) with two `cookie` fields, as browsers send them.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let public = s.gw.public;
        let hv = h.clone();
        let status = rt.block_on(async move {
            let client = reqwest::Client::builder()
                .http2_prior_knowledge()
                .no_proxy()
                .resolve(APP_HOST, public)
                .build()
                .expect("h2 client");
            let resp = client
                .get(format!("http://{APP_HOST}:{}/admin/x", public.port()))
                .header("x-forwarded-for", "192.0.2.10")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-port", "443")
                .header("x-forwarded-host", APP_HOST)
                .header("sec-fetch-dest", "document")
                .header("sec-fetch-mode", "navigate")
                .header("accept", "text/html")
                .header("cookie", "a=b")
                .header(reqwest::header::COOKIE, format!("__Host-hopae={hv}"))
                .send()
                .await
                .expect("h2 request");
            assert_eq!(resp.version(), reqwest::Version::HTTP_2);
            resp.status().as_u16()
        });
        assert_eq!(status, 200);
        let calls = s.gw.tap.calls();
        assert_eq!(calls.len(), 1);
        let cookies: Vec<&str> = calls[0]
            .headers
            .iter()
            .filter(|(k, _)| k == "cookie")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies.len(), 1, "one cookie header at Hopae");
        assert_eq!(cookies[0], format!("a=b; __Host-hopae={h}"));
    }
}
