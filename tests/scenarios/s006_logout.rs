//! Scenario 006: logout ends access on every host.
//!
//! The termination, idempotence and race rules are tested in process against
//! the real store. The portal's pages, CSRF tokens and `Origin` checks (W1-E)
//! are `#[ignore]`d HTTP tests that run once the portal lands.
#![allow(dead_code, unused_imports)]

use hopae::crypto::{OsRng, Secret, random_token};
use hopae::event::types::{EventKind, reasons};
use hopae::session::{LoginEntry, LogoutOutcome, RedeemResult, SwitchChoice, SwitchOutcome};

use super::s002_oidc_login::kit::*;
use super::s003_handoff::switch_setup;
use crate::support::{Fixture, Hopae, Jar, MockIdp, VerifyRequest};

/// Session `s_1` with handles on the portal, `app` and `other`.
struct Signed {
    l: Logged,
    h1: Secret,
    h2: Secret,
}

async fn signed_in_everywhere(k: &Kit) -> Signed {
    let l = k.login().await;
    let RedeemResult::Minted { handle: h1, .. } =
        k.redeem(&l.code, &l.target, Some(&k.b1), None).await
    else {
        panic!("expected Minted")
    };
    let b2 = random_token(&OsRng, 16);
    let t2 = k.start(OTHER, "/", Some(&b2)).await;
    let LoginEntry::Sso { location, .. } = k
        .svc
        .sso_or_chooser(&k.ctx(), &t2.transaction, Some(&l.portal_handle), false)
        .await
        .unwrap()
    else {
        panic!("expected Sso")
    };
    let RedeemResult::Minted { handle: h2, .. } = k
        .redeem(
            &code_of(&location),
            &strip_handoff(&location),
            Some(&b2),
            None,
        )
        .await
    else {
        panic!("expected Minted")
    };
    Signed { l, h1, h2 }
}

/// Complete a login over HTTP against a spawned Hopae and return the portal
/// jar (holding `__Host-hopae` for the portal) and the application URL with
/// the handoff code. Follows only what the contract states.
fn http_login(h: &Hopae, idp: &MockIdp) -> (Jar, String) {
    let first =
        h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip("203.0.113.9"));
    assert_eq!(first.status, 302);
    let login_url = first.location().expect("login redirect").to_string();
    let path = login_url
        .split("auth.example.test")
        .nth(1)
        .expect("portal path")
        .to_string();
    let jar = Jar::new();
    let c = h.portal_with(jar.clone());
    let page = c.get(&path);
    let authorize = if page.status == 302 {
        page.location().expect("provider redirect").to_string()
    } else {
        // a chooser: post the form for the only provider
        let csrf = page
            .body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("csrf field")
            .to_string();
        let txn = path.split("txn=").nth(1).expect("txn").to_string();
        let r = c.post_form("/login/mock", &[("csrf", &csrf), ("txn", &txn)]);
        assert_eq!(r.status, 302);
        r.location().expect("provider redirect").to_string()
    };
    let state = url(&authorize)
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("state");
    let code = idp.issue_code(&state, "sub-1");
    let cb = c.get(&format!("/callback/mock?code={code}&state={state}"));
    assert_eq!(cb.status, 302);
    (jar, cb.location().expect("handoff redirect").to_string())
}

#[tokio::test]
#[ignore = "needs W1-E (portal listener)"]
async fn s006_1_confirmation_page() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-two-domains"), &idp, &[]);
    let (jar, _) = http_login(&h, &idp);
    let before = h.hooks.events(Some("session.terminated"), None).len();
    let r = h.portal_with(jar).get("/logout");
    assert_eq!(r.status, 200);
    assert!(
        r.body.contains("csrf"),
        "a form with a CSRF token bound to the portal handle"
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(
        h.hooks.events(Some("session.terminated"), None).len(),
        before,
        "no state change"
    );
}

#[tokio::test]
async fn s006_2_confirmed_logout_terminates_session() {
    let k = Kit::new().await;
    let s = signed_in_everywhere(&k).await;
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='{}'",
            s.l.session_id
        )),
        3
    );
    k.advance(10);
    let out = k
        .svc
        .logout(&k.ctx(), Some(&s.l.portal_handle))
        .await
        .unwrap();
    assert_eq!(
        out,
        LogoutOutcome::SignedOut {
            session_id: s.l.session_id.clone()
        }
    );
    assert_eq!(
        k.count("SELECT terminated_at FROM sessions"),
        k.now().secs()
    );
    assert_eq!(
        k.text("SELECT terminated_reason FROM sessions").as_deref(),
        Some("logout")
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NOT NULL"),
        3,
        "all three handles revoked"
    );
    let ev = k.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::LOGOUT));
    assert_eq!(ev[0].session_id.as_ref(), Some(&s.l.session_id));
    assert_eq!(ev[0].user_id.as_ref(), Some(&s.l.user_id));
    assert_eq!(
        k.count("SELECT COUNT(*) FROM event_deliveries d JOIN events e ON e.event_id=d.event_id WHERE e.kind='session.terminated'"),
        1,
        "the event travels with the termination"
    );
}

#[tokio::test]
async fn s006_3_next_request_denied_cookie_cleared() {
    // Verify's answer (302, cookie clear, `session_terminated`) is W1-A's; the
    // rows it decides on are these: the application handle resolves, but to a
    // revoked handle of a terminated session.
    let k = Kit::new().await;
    let s = signed_in_everywhere(&k).await;
    k.svc
        .logout(&k.ctx(), Some(&s.l.portal_handle))
        .await
        .unwrap();
    for (h, host_name) in [(&s.h1, APP), (&s.h2, OTHER)] {
        let view = k
            .store
            .sessions()
            .lookup_handle(&h.digest(), &host(host_name))
            .await
            .unwrap()
            .expect("the stale cookie is still known");
        assert!(view.handle.revoked_at.is_some(), "{host_name}");
        assert_eq!(
            view.handle.revoked_reason.as_deref(),
            Some("session_terminated")
        );
        assert_eq!(view.session.terminated_reason.as_deref(), Some("logout"));
    }
    // and no code of the session can still be redeemed
    let started = k.start(APP, "/x", Some(&k.b1)).await;
    let e = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &started.transaction,
            Some(&s.l.portal_handle),
            false,
        )
        .await
        .unwrap();
    assert!(
        matches!(e, LoginEntry::Chooser { .. }),
        "the portal handle no longer grants single sign-on"
    );
}

#[tokio::test]
async fn s006_4_logout_without_session() {
    let k = Kit::new().await;
    assert_eq!(
        k.svc.logout(&k.ctx(), None).await.unwrap(),
        LogoutOutcome::NoSession
    );
    let bogus = hopae::crypto::handle_value(&OsRng);
    assert_eq!(
        k.svc.logout(&k.ctx(), Some(&bogus)).await.unwrap(),
        LogoutOutcome::NoSession
    );
    let junk = Secret::new("garbage".into());
    assert_eq!(
        k.svc.logout(&k.ctx(), Some(&junk)).await.unwrap(),
        LogoutOutcome::NoSession
    );
    assert!(
        k.events(EventKind::SessionTerminated).await.is_empty(),
        "no event"
    );
    // a handle of an application host is not a portal handle
    let s = signed_in_everywhere(&k).await;
    assert_eq!(
        k.svc.logout(&k.ctx(), Some(&s.h1)).await.unwrap(),
        LogoutOutcome::NoSession
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions WHERE terminated_at IS NOT NULL"),
        0
    );
}

#[tokio::test]
async fn s006_5_switch_page_signs_out_other_account() {
    // choice=switch: the other handle is revoked with reason switch, V's session is untouched,
    // a fresh code for A is minted and the next redemption is A
    let k = Kit::new().await;
    let s = switch_setup(&k).await;
    let SwitchOutcome::Switched { location } = k
        .svc
        .switch_confirm(
            &k.ctx(),
            &s.ts,
            SwitchChoice::Switch,
            Some(&s.a.portal_handle),
        )
        .await
        .unwrap()
    else {
        panic!("expected Switched")
    };
    let revoked = k.events(EventKind::HandleRevoked).await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].reason, Some(reasons::SWITCH));
    assert_eq!(
        revoked[0].user_id.as_ref(),
        Some(&s.v.user_id),
        "the event names the signed-out account"
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE session_id='{}' AND terminated_at IS NULL",
            s.v.session_id
        )),
        1
    );
    let RedeemResult::Minted { handle, .. } = k
        .redeem(
            &code_of(&location),
            &strip_handoff(&location),
            Some(&k.b1),
            Some(&s.hy),
        )
        .await
    else {
        panic!("expected Minted")
    };
    let view = k
        .store
        .sessions()
        .lookup_handle(&handle.digest(), &host(APP))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.session.user_id, s.a.user_id, "the next verify is A");

    // choice=keep: nothing is revoked, the next verify is still V
    let k = Kit::new().await;
    let s = switch_setup(&k).await;
    let SwitchOutcome::Kept { location } = k
        .svc
        .switch_confirm(&k.ctx(), &s.ts, SwitchChoice::Keep, None)
        .await
        .unwrap()
    else {
        panic!("expected Kept")
    };
    assert_eq!(location.as_str(), "https://app.example.test/admin/x?a=1");
    assert!(k.events(EventKind::HandleRevoked).await.is_empty());
    let view = k
        .store
        .sessions()
        .lookup_handle(&s.hy.digest(), &host(APP))
        .await
        .unwrap()
        .unwrap();
    assert!(view.handle.revoked_at.is_none());
    assert_eq!(view.session.user_id, s.v.user_id);

    // without the incoming account's portal session (what a forged request has) nothing is revoked
    let k = Kit::new().await;
    let s = switch_setup(&k).await;
    assert!(
        k.svc
            .switch_confirm(&k.ctx(), &s.ts, SwitchChoice::Switch, None)
            .await
            .is_err()
    );
    assert!(k.events(EventKind::HandleRevoked).await.is_empty());
    assert!(
        k.store
            .sessions()
            .lookup_handle(&s.hy.digest(), &host(APP))
            .await
            .unwrap()
            .unwrap()
            .handle
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn s006_a1_replayed_logout_harmless() {
    let k = Kit::new().await;
    let s = signed_in_everywhere(&k).await;
    assert!(matches!(
        k.svc
            .logout(&k.ctx(), Some(&s.l.portal_handle))
            .await
            .unwrap(),
        LogoutOutcome::SignedOut { .. }
    ));
    // the same POST again: a signed-out page, no new event, no error
    assert_eq!(
        k.svc
            .logout(&k.ctx(), Some(&s.l.portal_handle))
            .await
            .unwrap(),
        LogoutOutcome::NoSession
    );
    assert_eq!(k.events(EventKind::SessionTerminated).await.len(), 1);
}

#[tokio::test]
#[ignore = "needs W1-E (portal listener)"]
async fn s006_a2_csrf_mismatch_rejected() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-two-domains"), &idp, &[]);
    let (jar, _) = http_login(&h, &idp);
    let c = h.portal_with(jar);
    for fields in [vec![], vec![("csrf", "not-a-token-of-this-session")]] {
        let r = c.post_form("/logout", &fields);
        assert_eq!(r.status, 403);
    }
    assert!(
        h.hooks.events(Some("session.terminated"), None).is_empty(),
        "session unchanged"
    );
    assert!(!h.hooks.events(Some("csrf.rejected"), None).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s006_a3_logout_racing_handoff() {
    // either the code is consumed first (a handle is created, then revoked by the
    // termination) or after (the redemption fails); in both orders no live handle remains
    let k = Kit::with(Opts {
        txn_per_ip: 10_000,
        failures_per_minute: 10_000,
        ..Opts::default()
    })
    .await;
    for round in 0..40 {
        let l = k.login().await;
        let ctx = k.ctx();
        let (r, out) = if round % 2 == 0 {
            tokio::join!(
                k.redeem(&l.code, &l.target, Some(&k.b1), None),
                k.svc.logout(&ctx, Some(&l.portal_handle))
            )
        } else {
            let (out, r) = tokio::join!(
                k.svc.logout(&ctx, Some(&l.portal_handle)),
                k.redeem(&l.code, &l.target, Some(&k.b1), None)
            );
            (r, out)
        };
        out.unwrap();
        let live = k.count(&format!(
            "SELECT COUNT(*) FROM session_handles h JOIN sessions s USING (session_id) WHERE h.session_id='{}' AND h.revoked_at IS NULL AND s.terminated_at IS NULL",
            l.session_id
        ));
        assert_eq!(live, 0, "round {round}: no usable handle after logout");
        if let RedeemResult::Minted { handle, .. } = r {
            let view = k
                .store
                .sessions()
                .lookup_handle(&handle.digest(), &host(APP))
                .await
                .unwrap()
                .unwrap();
            assert!(
                view.handle.revoked_at.is_some(),
                "round {round}: the new handle is already revoked"
            );
        }
    }
    // deterministic orders
    let l = k.login().await;
    k.svc
        .logout(&k.ctx(), Some(&l.portal_handle))
        .await
        .unwrap();
    match k.redeem(&l.code, &l.target, Some(&k.b1), None).await {
        RedeemResult::Login(_) => {}
        other => panic!("a code of a terminated session must not redeem, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs W1-E (portal listener)"]
async fn s006_a4_cross_site_logout_rejected() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-two-domains"), &idp, &[]);
    let (jar, _) = http_login(&h, &idp);
    let c = h.portal_with(jar.clone());
    // the page's token is irrelevant: the Origin is not the portal's
    let page = c.get("/logout");
    let csrf = page
        .body
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or("")
        .to_string();
    let r = c.send(
        crate::support::Req::post("/logout")
            .form(&[("csrf", &csrf)])
            .header("origin", "https://evil.example.org"),
    );
    assert_eq!(r.status, 403, "origin mismatch with the cookie present");
    assert!(
        h.hooks.events(Some("session.terminated"), None).is_empty(),
        "the session survives"
    );
    // without the cookie (Lax drops it on a cross-site POST) it is a no-op
    let anonymous = h.portal();
    let r = anonymous.send(
        crate::support::Req::post("/logout")
            .form(&[("csrf", "x")])
            .header("origin", "https://evil.example.org"),
    );
    assert!(r.status == 200 || r.status == 403);
    assert!(h.hooks.events(Some("session.terminated"), None).is_empty());
}

#[tokio::test]
async fn s006_a5_cannot_target_other_session() {
    let k = Kit::new().await;
    let one = k.login().await;
    k.mock
        .set_identity("sub-2", "b@example.test", true, false, "Bob");
    let two = k.login().await;
    assert_ne!(one.session_id, two.session_id);
    // the only input that selects a session is the caller's own portal handle
    k.svc
        .logout(&k.ctx(), Some(&one.portal_handle))
        .await
        .unwrap();
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE session_id='{}' AND terminated_at IS NOT NULL",
            one.session_id
        )),
        1
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE session_id='{}' AND terminated_at IS NULL",
            two.session_id
        )),
        1
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='{}' AND revoked_at IS NOT NULL",
            two.session_id
        )),
        0
    );
}
