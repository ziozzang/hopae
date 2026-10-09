//! Scenario 005: return targets are validated and never taken from the
//! client. The validation table is a unit test of the pure function; the
//! engine cases check what the engine does with the result.
#![allow(dead_code)]

use hopae::event::types::reasons;
use hopae::verify::{BindAction, DenyKind, Scheme};

use super::s004_verify::fx::*;
use crate::support::*;

fn two_domains() -> Fx {
    Fx::new("m1-two-domains")
}

#[tokio::test]
async fn s005_1_valid_target_round_trips_unchanged() {
    let f = two_domains();
    let url = "https://app.example.test:443/a/b?x=1%202&y=%2F";
    let (txn, bind, clear) = login(f.decide(f.req(url)).await);
    let txn = txn.expect("a transaction for a document navigation");
    assert!(matches!(bind, BindAction::Plant(_)) && !clear);
    let stored: String = f.sql(&format!(
        "SELECT return_target FROM login_txns WHERE txn_sha256 = x'{}'",
        txn.digest().to_hex()
    ));
    // The URL type drops the default port; every other byte is preserved
    // (path, query escapes and order).
    assert_eq!(stored, "https://app.example.test/a/b?x=1%202&y=%2F");
    let app: String = f.sql("SELECT app_id FROM login_txns");
    assert_eq!(app, "app");
    // The handoff target is the stored one plus the parameter, and removing
    // the parameter again gives the stored target back byte for byte.
    let with_param = format!("{stored}&_hopae_handoff=K");
    let clean = hopae::gateway::recognition::clean_target(&url::Url::parse(&with_param).unwrap());
    assert_eq!(clean.as_str(), stored);
}

#[test]
fn s005_2_validation_table() {
    let f = two_domains();
    let snapshot = f.snapshot.load_full();
    let table: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/return-targets.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(table.len(), 16);
    for row in table {
        let url = row["url"].as_str().unwrap();
        let expect = row["expect"].as_str().unwrap();
        let got = hopae::verify::return_target::validate(url, &snapshot, true);
        let shown: String = url.chars().take(60).collect();
        match (expect, got) {
            ("accept", Ok(u)) => {
                // Emitted lower-case.
                assert_eq!(u.host_str(), u.host_str().map(str::to_lowercase).as_deref());
            }
            ("accept", Err(r)) => panic!("{shown}: expected accept, got {}", r.0),
            (want, Ok(_)) => panic!("{shown}: expected {want}, got accept"),
            (want, Err(r)) => assert_eq!(r.0, want, "{shown}"),
        }
    }
    // The case-insensitive row is emitted lower-case.
    let u = hopae::verify::return_target::validate("https://APP.example.test/", &snapshot, true)
        .unwrap();
    assert_eq!(u.as_str(), "https://app.example.test/");
}

#[tokio::test]
async fn s005_3_only_exact_hosts_are_destinations() {
    let text = |hosts: &str| {
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m1-basic.json");
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        v["apps"][0]["hosts"] = serde_json::from_str(hosts).unwrap();
        v.to_string()
    };
    let Err(err) = hopae::config::parse(&text(r#"["*.example.test"]"#)) else {
        panic!("a wildcard host must be rejected")
    };
    assert!(err.to_string().contains("hosts"), "{err}");
    let cfg = hopae::config::parse(&text(r#"["App.Example.Test"]"#)).unwrap();
    assert!(cfg.warnings().iter().any(|w| w.contains("lower case")));
    assert_eq!(
        cfg.snapshot(1).apps[0].hosts[0].as_str(),
        "app.example.test"
    );

    let f = Fx::new("m1-basic");
    let (reason, kind) = deny(f.decide(f.req("https://new.example.test/")).await);
    assert_eq!(reason, reasons::UNKNOWN_APP);
    assert_eq!(kind, DenyKind::Forbidden);
    assert_eq!(f.txn_rows(), 0, "no transaction");
}

#[test]
fn s005_a1_portal_parameters_cannot_alter_target() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.verify(VerifyRequest::document("https://app.example.test/a"));
    let txn = r
        .location()
        .unwrap()
        .split("txn=")
        .nth(1)
        .unwrap()
        .to_string();
    let p = h.portal();
    let go = p.get(&format!(
        "/login?txn={txn}&redirect_uri=https://evil.example.org/"
    ));
    if let Some(l) = go.location() {
        assert!(!l.contains("evil.example.org"), "{l}");
    }
    let bare = p.get("/login?rd=https://evil.example.org/");
    assert_eq!(bare.status, 400);
    assert!(bare.location().is_none());
}

#[test]
fn s005_a2_pathological_urls_bounded() {
    let f = two_domains();
    let snapshot = f.snapshot.load_full();
    let huge = format!("https://app.example.test/{}", "a".repeat(64 * 1024));
    let many = format!("https://app.example.test/?{}", "a=1&".repeat(10_000));
    for url in [huge, many] {
        let started = std::time::Instant::now();
        let r = hopae::verify::return_target::validate(&url, &snapshot, true);
        assert_eq!(r.err().map(|r| r.0), Some("too_long"));
        assert!(started.elapsed() < std::time::Duration::from_millis(1));
    }
}

#[test]
fn s005_a3_provider_redirect_ignored() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.verify(VerifyRequest::document("https://app.example.test/a"));
    let txn = r
        .location()
        .unwrap()
        .split("txn=")
        .nth(1)
        .unwrap()
        .to_string();
    // One browser: the portal binding cookie planted by /login must come back on the callback.
    let portal = h.portal();
    let go = portal.get(&format!("/login?txn={txn}"));
    // Single provider: straight to the provider; the flow is then completed at
    // the mock and the callback carries an extra `next` parameter.
    let authorize = go.location().expect("provider redirect").to_string();
    assert!(authorize.starts_with(idp.issuer.as_str()));
    // The browser follows the provider; the callback then carries an extra `next` parameter.
    let callback = idp.follow_authorization(&authorize);
    let cb = portal.get(&format!("{callback}&next=https://evil.example.org/"));
    let loc = cb.location().expect("handoff redirect");
    assert!(
        loc.starts_with("https://app.example.test/a?_hopae_handoff="),
        "{loc}"
    );
}

#[tokio::test]
async fn s005_a4_host_case_and_trailing_dot() {
    let f = two_domains();
    // Mixed case folds to the registered name and is accepted.
    let (txn, _, _) = login(
        f.decide(f.req("https://App.Example.Test/").host("App.Example.Test"))
            .await,
    );
    assert!(txn.is_some());
    // A trailing dot is a different name: unknown unless registered.
    let url = url::Url::parse("https://app.example.test./").unwrap();
    assert_eq!(url.host_str(), Some("app.example.test."));
    let r = hopae::verify::return_target::validate(url.as_str(), &f.snapshot.load_full(), true);
    assert_eq!(r.err().map(|r| r.0), Some("unknown_app"));
    // The adapter's `Host::parse` refuses the trailing-dot form too.
    assert!(hopae::policy::types::Host::parse("app.example.test.").is_err());
}

#[tokio::test]
async fn s005_a5_scheme_downgrade_only_in_dev_mode() {
    // Secure (default): a plain-http target and a plain-http transport are refused.
    let f = Fx::new("m1-basic");
    let (reason, kind) = deny(
        f.decide(f.req("http://app.example.test/").proto(Scheme::Http))
            .await,
    );
    assert_eq!(reason, reasons::INSECURE_TRANSPORT);
    assert_eq!(kind, DenyKind::ContractViolation);
    assert_eq!(f.txn_rows(), 0);
    // Development fixture: the same request is accepted.
    let f = Fx::new("m1-dev-insecure");
    let (txn, _, _) = login(f.decide(f.req("http://app.example.test/")).await);
    assert!(txn.is_some());
    let target: String = f.sql("SELECT return_target FROM login_txns");
    assert_eq!(target, "http://app.example.test/");
    assert!(f.cfg.insecure_mode());
}

#[tokio::test]
async fn s005_a6_no_host_enumeration() {
    let f = Fx::with("m1-two-domains", |v| v["apps"][1]["enabled"] = false.into());
    let unknown = deny(f.decide(f.req("https://nope.example.test/")).await);
    let disabled = deny(f.decide(f.req("https://other.example.org/")).await);
    // Same status class and body; the reasons differ (events only).
    assert_eq!(unknown.1, disabled.1);
    assert_eq!(unknown.0, reasons::UNKNOWN_APP);
    assert_eq!(disabled.0, reasons::APP_DISABLED);
    assert_eq!(f.txn_rows(), 0);
}

/// G7-C05: a return target within the 2048-byte limit stays valid when Hopae
/// appends its handoff parameter. Complete flows at 1990 and exactly 2048 bytes.
#[test]
fn g7_c05_targets_near_the_limit_complete_the_handoff() {
    for len in [1990usize, 2048] {
        let prefix = "https://app.example.test/p?q=";
        let url = format!("{prefix}{}", "a".repeat(len - prefix.len()));
        assert_eq!(url.len(), len);
        let (handoff, redeem, clean) =
            super::s011_ip_binding::full_login_flow(serde_json::json!({}), &url, None);
        assert!(
            handoff.len() > len,
            "the code is appended: {}",
            handoff.len()
        );
        assert_eq!(
            redeem.status, 302,
            "redemption of a {len}-byte target: {redeem:?}"
        );
        assert_eq!(redeem.location(), Some(url.as_str()));
        assert_eq!(clean.status, 200, "the clean {len}-byte request");
    }
}

// ---- gateway layer (W2-A) ---------------------------------------------------

mod gateway_layer {
    use crate::support::gateway::*;

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s005_a7_host_neutral_route_attacker_host_denied() {
        // A protected route without host/hosts: any Host reaches Hopae's verify, and
        // the gateway builds x-original-url from the (syntax-checked) client Host.
        let Some(s) = Stack::with_routes(
            "s005_a7",
            GatewayRoutes::new()
                .host_neutral("/admin")
                .portal(PORTAL_HOST),
        ) else {
            return;
        };
        let b = s.gw.browser();

        let evil = b.get("evil.example.org", "/admin/x");
        assert_eq!(evil.status, 403, "relayed to the client: {evil:?}");
        let calls = s.gw.tap.calls();
        assert_eq!(calls.len(), 1, "the route called Hopae");
        assert!(
            calls[0]
                .header("x-original-url")
                .is_some_and(|u| u.starts_with("https://evil.example.org/")),
            "{:?}",
            calls[0].header("x-original-url")
        );
        let answer = s.gw.tap.answers().pop().unwrap();
        assert_eq!(answer.status, 403);
        assert_eq!(answer.header("x-hopae-reason"), Some("unknown_app"));
        assert!(evil.set_cookies().is_empty(), "no binding cookie: {evil:?}");
        assert_eq!(txn_count(&s.hopae), 0, "no transaction");
        assert!(evil.location().is_none());
        assert!(s.echo.requests().is_empty());

        // The registered host gets the normal 302 with a transaction for that host.
        let ok = b.get(APP_HOST, "/admin/x");
        assert_eq!(ok.status, 302, "{ok:?}");
        assert!(
            ok.location()
                .unwrap()
                .starts_with("https://auth.example.test/login?txn=")
        );
        assert_eq!(
            return_target(&s.hopae, &txn_of(&ok)).as_deref(),
            Some("https://app.example.test/admin/x")
        );
        assert_eq!(txn_count(&s.hopae), 1);
        // No Location Hopae emitted names a host outside the allowlist.
        for a in s.gw.tap.answers() {
            if let Some(l) = a.header("location") {
                assert!(!l.contains("evil.example.org"), "{l}");
            }
        }
    }
}
