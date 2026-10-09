//! Scenario 011: client-IP (and user-agent) binding at verify. Engine-level
//! over a real store; S011-6 is the portal's and S011-A5 the adapter's.
#![allow(dead_code)]

use hopae::crypto::{Secret, sha256};
use hopae::event::types::{ATTR_ALLOWLIST, EventKind, reasons};
use hopae::verify::Decision;

use super::s004_verify::fx::*;
use crate::support::*;

const BOUND: &str = "203.0.113.9";
const FAR: &str = "198.51.100.7";
const RELAXED_URL: &str = "https://relaxed.example.test/";
const OPEN_URL: &str = "https://open.example.test/";

struct Bound {
    f: Fx,
    s: Sess,
    h1: Secret,
    h2: Secret,
    h3: Secret,
}

/// Session `s_1` created from 203.0.113.9 with `user-agent: UA1`; handles H0
/// (portal), H1 (`app`), H2 (`relaxed`), H3 (`open`).
async fn bound_with(f: Fx) -> Bound {
    let u = f.user("a@example.test", Some("alice"), None).await;
    let s = f
        .session_with(&u, |r| {
            r.bound_ip = ip(BOUND);
            r.bound_ua_sha256 = Some(sha256(b"UA1"));
        })
        .await;
    let h1 = f.handle(&s, "app.example.test").await;
    let h2 = f.handle(&s, "relaxed.example.test").await;
    let h3 = f.handle(&s, "open.example.test").await;
    Bound { f, s, h1, h2, h3 }
}

async fn bound() -> Bound {
    bound_with(Fx::new("m1-binding")).await
}

#[tokio::test]
async fn s011_1_same_ip_allowed() {
    let b = bound().await;
    allow(
        b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND).ua("UA1"))
            .await,
    );
}

#[tokio::test]
async fn s011_2_different_ip_terminates_session() {
    let b = bound().await;
    let (txn, _, clear) = login(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(FAR)).await);
    assert!(txn.is_some() && clear);
    assert_eq!(b.f.session_state(&b.s).0.as_deref(), Some("binding_ip"));
    for h in [&b.h1, &b.h2, &b.h3, &b.s.portal] {
        assert_eq!(b.f.handle_state(h).0.as_deref(), Some("session_terminated"));
    }
    let ev = b.f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::BINDING_IP));
    assert_eq!(ev[0].client_ip, Some(ip(FAR)), "the observed address");
    if ATTR_ALLOWLIST.contains(&"bound_ip") {
        // Active once W0 allowlists `bound_ip`/`observed_ip` (report request R2).
        assert_eq!(ev[0].attrs["bound_ip"], BOUND);
        assert_eq!(ev[0].attrs["observed_ip"], FAR);
    }
    // A following verify from the original IP is also denied.
    let (txn, _, _) = login(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND)).await);
    assert!(txn.is_some());
}

#[tokio::test]
async fn s011_3_prefix_mode_and_drop_handle() {
    let b = bound().await;
    allow(
        b.f.decide(b.f.req(RELAXED_URL).cookie(&b.h2).ip("203.0.113.200"))
            .await,
    );
    let (_, _, clear) = login(
        b.f.decide(b.f.req(RELAXED_URL).cookie(&b.h2).ip("203.0.114.1"))
            .await,
    );
    assert!(clear);
    assert_eq!(b.f.handle_state(&b.h2).0.as_deref(), Some("binding_ip"));
    assert_eq!(b.f.session_state(&b.s).0, None, "session alive");
    allow(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND)).await);
    let ev = b.f.events(EventKind::HandleRevoked).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::BINDING_IP));
}

#[tokio::test]
async fn s011_4_off_mode_ignores_ip() {
    let b = bound().await;
    allow(b.f.decide(b.f.req(OPEN_URL).cookie(&b.h3).ip(FAR)).await);
}

#[tokio::test]
async fn s011_5_ua_binding_when_enabled() {
    let strict_ua = |v: &mut serde_json::Value| v["apps"][0]["binding"]["ua"] = "strict".into();
    let b = bound_with(Fx::with("m1-binding", strict_ua)).await;
    allow(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ua("UA1")).await);
    let (_, _, clear) = login(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ua("UA2")).await);
    assert!(clear);
    assert_eq!(b.f.session_state(&b.s).0.as_deref(), Some("binding_ua"));
    let ev = b.f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::BINDING_UA));
    // Digests only: no raw user-agent value in any attribute.
    assert_eq!(ev[0].ua_sha256, Some(sha256(b"UA2")));
    for v in ev[0].attrs.values() {
        assert_ne!(v, "UA1");
        assert_ne!(v, "UA2");
    }
    if ATTR_ALLOWLIST.contains(&"recorded_sha256") {
        assert_eq!(ev[0].attrs["recorded_sha256"], sha256(b"UA1").to_hex());
        assert_eq!(ev[0].attrs["observed_sha256"], sha256(b"UA2").to_hex());
    }
}

#[test]
fn s011_6_txn_inherits_policy() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .ip("203.0.113.9")
            .ua("UA1"),
    );
    assert_eq!(r.status, 302);
    let txn = r
        .location()
        .unwrap()
        .split("txn=")
        .nth(1)
        .unwrap()
        .to_string();
    let other = h
        .portal()
        .with_ip("198.51.100.7")
        .get(&format!("/login?txn={txn}"));
    assert_eq!(other.status, 400);
    // S001-A3: the refused transaction is consumed, so the original client
    // restarts too; its fresh transaction, from its own address, proceeds.
    let again = h
        .portal()
        .with_ip("203.0.113.9")
        .get(&format!("/login?txn={txn}"));
    assert_eq!(again.status, 400, "the consumed transaction stays refused");
    let r = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .ip("203.0.113.9")
            .ua("UA1"),
    );
    let txn2 = r
        .location()
        .unwrap()
        .split("txn=")
        .nth(1)
        .unwrap()
        .to_string();
    let own = h
        .portal()
        .with_ip("203.0.113.9")
        .get(&format!("/login?txn={txn2}"));
    assert_ne!(own.status, 400);
}

#[tokio::test]
async fn s011_a1_stolen_cookie_from_other_network() {
    let b = bound().await;
    let attacker = b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(FAR)).await;
    assert!(!matches!(attacker, Decision::Allow { .. }));
    // The victim's next request is refused as well and sent to log in again.
    let (txn, _, clear) = login(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND)).await);
    assert!(txn.is_some() && clear);
    let ev = b.f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].client_ip, Some(ip(FAR)));
}

#[tokio::test]
async fn s011_a2_ip_forms_normalized() {
    use hopae::policy::binding::{BindingVerdict, check, ip_matches};
    use hopae::policy::types::{BindingPolicy, IpBinding};
    let strict = BindingPolicy::default();
    assert_eq!(
        check(
            &strict,
            ip("::ffff:203.0.113.9"),
            None,
            ip("203.0.113.9"),
            None
        ),
        BindingVerdict::Ok
    );
    let prefix = IpBinding::Prefix { v4: 24, v6: 64 };
    assert!(ip_matches(
        prefix,
        ip("2001:db8:0:1::1"),
        ip("2001:db8:0:1:ffff::2")
    ));
    assert!(!ip_matches(
        prefix,
        ip("2001:db8:0:1::1"),
        ip("2001:db8:0:2::1")
    ));

    // Through the engine: a session bound to the mapped form accepts the plain one.
    let f = Fx::new("m1-binding");
    let u = f.user("a@example.test", Some("alice"), None).await;
    let s = f
        .session_with(&u, |r| r.bound_ip = ip("::ffff:203.0.113.9"))
        .await;
    let h = f.handle(&s, "app.example.test").await;
    allow(f.decide(f.req(APP_URL).cookie(&h).ip("203.0.113.9")).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s011_a3_concurrent_requests_two_ips() {
    for _ in 0..25 {
        let b = bound().await;
        let (near, far) = tokio::join!(
            b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND)),
            b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(FAR)),
        );
        assert!(
            !matches!(far, Decision::Allow { .. }),
            "the far request is never allowed"
        );
        let allows = usize::from(matches!(near, Decision::Allow { .. }));
        assert!(allows <= 1);
        assert_eq!(
            b.f.session_state(&b.s).0.as_deref(),
            Some("binding_ip"),
            "terminated regardless of order"
        );
    }
}

#[tokio::test]
async fn s011_a4_drop_handle_dos_bounded() {
    let b = bound().await;
    for _ in 0..100 {
        let d =
            b.f.decide(b.f.req(RELAXED_URL).cookie(&b.h2).ip("192.0.2.77"))
                .await;
        assert!(!matches!(d, Decision::Allow { .. }));
    }
    assert_eq!(
        b.f.events(EventKind::HandleRevoked).await.len(),
        1,
        "revoked once"
    );
    assert_eq!(b.f.session_state(&b.s).0, None);
    allow(b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(BOUND)).await);
    assert_eq!(b.f.handle_state(&b.s.portal).0, None);
}

#[test]
fn s011_a5_forwarded_for_list_rejected() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let dup = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .header("x-forwarded-for", "198.51.100.7"),
    );
    assert_eq!(dup.status, 400);
    assert_eq!(dup.header("x-hopae-reason"), Some("contract_violation"));
    let list = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .without("x-forwarded-for")
            .header("x-forwarded-for", "203.0.113.9, 10.0.0.1"),
    );
    assert_eq!(list.status, 400);
}

#[tokio::test]
async fn s011_a6_policy_not_relaxable_by_request() {
    // The policy comes from the application's configuration only: nothing in
    // the engine's input can switch it off (a `x-hopae-binding: off` header
    // is not even part of `VerifyInput`; the adapter ignores it).
    let b = bound().await;
    let d = b.f.decide(b.f.req(APP_URL).cookie(&b.h1).ip(FAR)).await;
    assert!(!matches!(d, Decision::Allow { .. }));
    assert_eq!(b.f.session_state(&b.s).0.as_deref(), Some("binding_ip"));
}
