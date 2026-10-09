//! Scenario 003: the cross-host handoff plants a host-only cookie.
//!
//! W1-D tests the handoff in process: minting at the portal, redemption on the
//! application host (`Service::redeem`), single sign-on, the account switch
//! and the recovery rules, against the real SQLite store. The cases of kind
//! `gateway` (s003_5, s003_7, s003_a5, s003_a9, s003_a13) belong to W2-A.
//! Cases whose assertions are about the wire of other tasks (the verify
//! response, the portal listener) are `#[ignore]`d HTTP tests.
#![allow(dead_code, unused_imports)]

use std::time::Duration;

use hopae::crypto::{OsRng, Secret, handle_value, random_token};
use hopae::event::types::{EventKind, reasons};
use hopae::policy::types::Host;
use hopae::session::{Aal, LoginEntry, SessionError, SwitchChoice, SwitchOutcome};
use hopae::verify::types::BindAction;
use url::Url;

use super::s002_oidc_login::kit::*;
use crate::support::{Fixture, Hopae, MockIdp, VerifyRequest};

fn minted(r: RedeemResult) -> (Url, Secret, Aal, Duration) {
    match r {
        RedeemResult::Minted {
            location,
            handle,
            issued_aal,
            max_age,
            ..
        } => (location, handle, issued_aal, max_age),
        other => panic!("expected Minted, got {other:?}"),
    }
}

fn login_started(r: RedeemResult) -> StartedLogin {
    match r {
        RedeemResult::Login(s) => s,
        other => panic!("expected Login, got {other:?}"),
    }
}

async fn rejected_reasons(k: &Kit) -> Vec<String> {
    // Events written in the same millisecond have no defined relative order: compare sorted.
    let mut v: Vec<String> = k
        .events(EventKind::HandoffRejected)
        .await
        .into_iter()
        .map(|e| e.reason.map(|r| r.0.to_string()).unwrap_or_default())
        .collect();
    v.sort();
    v
}

fn fresh_bind() -> Secret {
    random_token(&OsRng, 16)
}

// ---- main flow --------------------------------------------------------------

#[tokio::test]
async fn s003_1_valid_code_plants_cookie() {
    let k = Kit::new().await;
    let l = k.login().await;
    k.advance(5);
    let (location, h1, aal, max_age) =
        minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);

    assert_eq!(location, l.target, "the clean URL, without the parameter");
    assert_eq!(location.as_str(), "https://app.example.test/admin/x?a=1");
    assert_eq!(aal, Aal::One);
    assert_eq!(
        max_age,
        Duration::from_secs(7 * 86400),
        "Max-Age is the handle's remaining absolute lifetime"
    );
    assert_eq!(
        k.count(&format!("SELECT COUNT(*) FROM handoff_codes WHERE code_sha256 = x'{}' AND consumed_at IS NOT NULL AND consumed_reason='redeemed'", l.code.digest())),
        1
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE handle_sha256 = x'{}' AND session_id='{}' AND host='{APP}' AND issued_aal=1",
            h1.digest(),
            l.session_id
        )),
        1,
        "stored as a digest, bound to (session, host) with the issued level"
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='{}'",
            l.session_id
        )),
        2,
        "portal + application"
    );
    let ev = k.events(EventKind::SessionHandoff).await;
    assert_eq!(ev.len(), 1, "session.handoff in the redeeming transaction");
    assert_eq!(ev[0].attrs.get("host").and_then(|h| h.as_str()), Some(APP));
    assert_eq!(
        ev[0].attrs.get("sso"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(ev[0].session_id.as_ref(), Some(&l.session_id));
    // the bind cookie is not the service's to change: redemption returns nothing about it
    assert!(rejected_reasons(&k).await.is_empty());
}

#[tokio::test]
async fn s003_2_other_query_parameters_preserved() {
    let k = Kit::new().await;
    // the reserved parameter is appended last and every other byte of the query is kept
    for pq in [
        "/admin/x?q=1&z=2",
        "/admin/x?q=1&k=%2B&z=%E2%9C%93",
        "/admin/x?x",
        "/admin/x",
    ] {
        let l = k.login_to(APP, pq).await;
        let query = l.location.query().unwrap();
        assert!(
            query.ends_with(&format!("_hopae_handoff={}", l.code.expose())),
            "{query}"
        );
        assert_eq!(
            l.target.as_str(),
            format!("https://{APP}{pq}"),
            "stripping gives the original target back"
        );
        assert_eq!(l.location.path(), "/admin/x");
        let (location, _, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
        assert_eq!(
            location.as_str(),
            format!("https://{APP}{pq}"),
            "no reordering, no double '?', no re-encoding"
        );
    }
    // The adapter owns query parsing (ADR-0013, R-1): a URL that carries the
    // reserved parameter, literally or by encoded alias, reaches the engine
    // with the pair removed and the code extracted, so a transaction can never
    // be created for a target that holds the parameter.
    use hopae::gateway::recognition::{clean_target, find_handoff};
    use hopae::verify::types::Handoff;
    for (raw, want) in [
        ("/x?_hopae_handoff=K", "/x"),
        ("/x?a=1&%5Fhopae%5Fhandoff=K", "/x?a=1"),
        ("/x?q=1&_hopae_handoff=K1%2B&z=2", "/x?q=1&z=2"),
    ] {
        let u = url(&format!("https://{APP}{raw}"));
        assert!(
            matches!(find_handoff(u.query().unwrap()), Handoff::Code(_)),
            "{raw}"
        );
        assert_eq!(
            clean_target(&u).as_str(),
            format!("https://{APP}{want}"),
            "{raw}"
        );
        let started = k.start(APP, want, Some(&k.b1)).await;
        let row = k
            .store
            .sessions()
            .transaction(&started.transaction.digest())
            .await
            .unwrap()
            .unwrap();
        assert!(
            !row.return_target.as_str().contains("hopae_handoff"),
            "{raw}"
        );
    }
}

#[tokio::test]
async fn s003_3_next_request_allowed() {
    // The 200 and the identity headers are verify's (scenario 004); what the
    // handoff must leave behind is the row verify reads: a live handle for
    // (session, host) at the issued level, found by its digest on that host
    // only, for an active user.
    let k = Kit::new().await;
    let l = k.login().await;
    let (_, h1, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let view = k
        .store
        .sessions()
        .lookup_handle(&h1.digest(), &host(APP))
        .await
        .unwrap()
        .expect("the handle resolves on its host");
    assert_eq!(view.session.session_id, l.session_id);
    assert_eq!(view.handle.issued_aal, Aal::One);
    assert!(view.handle.revoked_at.is_none() && view.session.terminated_at.is_none());
    assert_eq!(view.user.status, hopae::store::types::UserStatus::Active);
    assert!(
        k.store
            .sessions()
            .lookup_handle(&h1.digest(), &host(OTHER))
            .await
            .unwrap()
            .is_none(),
        "a handle is useless on another host"
    );
    assert!(
        k.store
            .sessions()
            .lookup_handle(&h1.digest(), &host(PORTAL))
            .await
            .unwrap()
            .is_none(),
        "and on the portal"
    );
}

#[tokio::test]
async fn s003_4_second_domain_via_sso() {
    let k = Kit::new().await;
    let l = k.login().await;
    let (_, _h1, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);

    // the second host: its own transaction and its own bind cookie
    let b2 = fresh_bind();
    let t2 = k.start(OTHER, "/", Some(&b2)).await;
    let LoginEntry::Sso { location, .. } = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&l.portal_handle),
            None,
            false,
        )
        .await
        .unwrap()
    else {
        panic!("expected Sso")
    };
    let target = strip_handoff(&location);
    assert_eq!(target.as_str(), "https://other.example.org/");
    let (_, h2, _, _) = minted(
        k.redeem(&code_of(&location), &target, Some(&b2), None)
            .await,
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE handle_sha256 = x'{}' AND host='{OTHER}'",
            h2.digest()
        )),
        1
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='{}'",
            l.session_id
        )),
        3
    );
    assert_eq!(
        k.mock.completes(),
        1,
        "no provider interaction for the second host"
    );

    // portal.sso_confirm_new_host: one click before the first handoff to a host
    let k = Kit::with(Opts {
        sso_confirm: true,
        ..Opts::default()
    })
    .await;
    let l = k.login().await;
    minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let t2 = k.start(OTHER, "/", Some(&b2)).await;
    let first = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&l.portal_handle),
            None,
            false,
        )
        .await
        .unwrap();
    let LoginEntry::ConfirmNewHost {
        host: confirm_host, ..
    } = first
    else {
        panic!("expected ConfirmNewHost, got {first:?}")
    };
    assert_eq!(confirm_host.as_str(), OTHER);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM handoff_codes WHERE host='other.example.org'"),
        0,
        "nothing minted before the click"
    );
    let second = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&l.portal_handle),
            None,
            true,
        )
        .await
        .unwrap();
    assert!(matches!(second, LoginEntry::Sso { .. }));
    // the host the session was already handed off to needs no click
    let t3 = k.start(APP, "/again", Some(&k.b1)).await;
    let again = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &t3.transaction,
            Some(&l.portal_handle),
            None,
            false,
        )
        .await
        .unwrap();
    assert!(matches!(again, LoginEntry::Sso { .. }), "{again:?}");
}

#[tokio::test]
async fn s003_6_already_redeemed_code_clean_redirect() {
    let k = Kit::new().await;
    let l = k.login().await;
    let (_, h1, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let handles = k.count("SELECT COUNT(*) FROM session_handles");
    // the navigation still carries K1 and the browser now holds H1
    match k.redeem(&l.code, &l.target, Some(&k.b1), Some(&h1)).await {
        RedeemResult::AlreadyRedeemed { location } => assert_eq!(location, l.target),
        other => panic!("expected AlreadyRedeemed, got {other:?}"),
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles"),
        handles,
        "no new handle, no cookie change"
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NOT NULL"),
        0
    );
    assert!(
        rejected_reasons(&k).await.is_empty(),
        "no handoff.rejected for an idempotent navigation"
    );
    assert_eq!(k.events(EventKind::SessionHandoff).await.len(), 1);
    // the handle still works
    assert!(
        k.store
            .sessions()
            .lookup_handle(&h1.digest(), &host(APP))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn s003_8_concurrent_transactions_share_bind() {
    for first_a in [true, false] {
        let k = Kit::new().await;
        // tab A started a login (bind B1 planted); tab B starts another with the cookie present
        let ta = k.start(APP, "/a", Some(&k.b1)).await;
        let tb = k.start(APP, "/b", Some(&k.b1)).await;
        assert!(matches!(ta.bind, BindAction::Keep) && matches!(tb.bind, BindAction::Keep));
        let rows: Vec<Vec<u8>> = {
            let conn = k.store.conn();
            let mut st = conn.prepare("SELECT bind_sha256 FROM login_txns").unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(|b| b.as_slice() == k.b1.digest().0),
            "both transactions store sha256(B1)"
        );

        // at the portal both coexist under the same portal cookie
        let sa = k.redirect(&ta.transaction, &k.p1).await;
        let sb = k.redirect(&tb.transaction, &k.p1).await;
        let a = k.logged(
            k.callback(&sa, Some(&k.p1), None).await.unwrap(),
            ta.transaction,
        );
        let b = k.logged_reused(
            k.callback(&sb, Some(&k.p1), Some(&a.portal_handle))
                .await
                .unwrap(),
            tb.transaction,
        );
        assert_eq!(a.session_id, b.session_id);

        // both codes redeem, in either order; the second replaces the handle of the same session
        let ((first, fb), (second, sb_)) = if first_a {
            ((&a, "a"), (&b, "b"))
        } else {
            ((&b, "b"), (&a, "a"))
        };
        let (_, h1, _, _) = minted(
            k.redeem(&first.code, &first.target, Some(&k.b1), None)
                .await,
        );
        let (_, h2, _, _) = minted(
            k.redeem(&second.code, &second.target, Some(&k.b1), Some(&h1))
                .await,
        );
        let _ = (fb, sb_);
        assert_ne!(h1.digest(), h2.digest());
        assert_eq!(
            k.count(&format!(
                "SELECT COUNT(*) FROM session_handles WHERE host='{APP}' AND revoked_at IS NULL"
            )),
            1
        );
        assert_eq!(k.count(&format!("SELECT COUNT(*) FROM session_handles WHERE host='{APP}' AND revoked_reason='replaced'")), 1);
    }
}

impl Kit {
    /// A callback outcome that reused the portal session.
    fn logged_reused(&self, out: hopae::session::CallbackOutcome, txn: Secret) -> Logged {
        match out {
            hopae::session::CallbackOutcome::LoggedIn {
                location,
                session_id,
                user_id,
                portal_handle,
                reused_session,
                ..
            } => {
                assert!(
                    reused_session && portal_handle.is_none(),
                    "same user with a valid portal handle reuses the session"
                );
                Logged {
                    code: code_of(&location),
                    target: strip_handoff(&location),
                    location,
                    session_id,
                    user_id,
                    portal_handle: Secret::new(String::new()),
                    txn,
                }
            }
            other => panic!("expected LoggedIn, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn s003_9_first_use_tab_race_recovers() {
    // (loser's bind, jar's bind): the tab that completes first got a bind the jar no longer holds
    for loser in [0, 1] {
        let k = Kit::new().await;
        let b_a = fresh_bind(); // tab A's bind (the one that completes first)
        let b_b = fresh_bind(); // tab B's bind
        let (b_first, b_jar) = if loser == 0 {
            (b_a.clone(), b_b.clone())
        } else {
            (b_b.clone(), b_a.clone())
        };
        let ta = k.start(APP, "/admin/x", Some(&b_first)).await;
        let tb = k.start(APP, "/admin/y", Some(&b_jar)).await;

        // tab A completes the provider login first
        let sa = k.redirect(&ta.transaction, &k.p1).await;
        let a = k.logged(
            k.callback(&sa, Some(&k.p1), None).await.unwrap(),
            ta.transaction,
        );

        // A navigates with the jar's bind and no handle: KA is burned, the answer is the
        // ordinary unauthenticated 302 that keeps the jar's bind, at depth 1
        let started = login_started(k.redeem(&a.code, &a.target, Some(&b_jar), None).await);
        assert!(
            matches!(started.bind, BindAction::Keep),
            "no new bind value"
        );
        let row = k
            .store
            .sessions()
            .transaction(&started.transaction.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.recovery_depth, 1);
        assert_eq!(row.bind_sha256, Some(b_jar.digest()));
        assert_eq!(rejected_reasons(&k).await, vec!["bind_mismatch"]);
        assert_eq!(
            k.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_reason='bind_mismatch'"),
            1
        );

        // the portal holds the handle, so it hands off at once; the new code carries the depth
        let LoginEntry::Sso { location, .. } = k
            .svc
            .sso_or_chooser(
                &k.ctx(),
                &started.transaction,
                Some(&a.portal_handle),
                None,
                false,
            )
            .await
            .unwrap()
        else {
            panic!("expected Sso")
        };
        assert_eq!(k.count("SELECT recovery_depth FROM handoff_codes ORDER BY created_at DESC, rowid DESC LIMIT 1"), 1);
        let (_, h1, _, _) = minted(
            k.redeem(
                &code_of(&location),
                &strip_handoff(&location),
                Some(&b_jar),
                None,
            )
            .await,
        );

        // tab B's callback completes with the same portal cookie: no second session, and
        // KB (bound to the jar's bind) redeems, replacing H1 with a handle of the same session
        let sb = k.redirect(&tb.transaction, &k.p1).await;
        let b = k.logged_reused(
            k.callback(&sb, Some(&k.p1), Some(&a.portal_handle))
                .await
                .unwrap(),
            tb.transaction,
        );
        assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
        let (_, h2, _, _) = minted(k.redeem(&b.code, &b.target, Some(&b_jar), Some(&h1)).await);
        assert_ne!(h1.digest(), h2.digest());
        assert_eq!(
            k.count(&format!(
                "SELECT COUNT(*) FROM session_handles WHERE host='{APP}' AND revoked_at IS NULL"
            )),
            1
        );
    }
    // the bounded, server-side recovery depth (S003-A13 at service level)
    recovery_depth_chain().await;
}

/// The depth chain of S003-A13 at service level: a browser with a broken
/// cookie jar (it never presents a bind) is sent round the portal at depths
/// 1, 2, 3 and then stopped without a transaction; depth is read only from the
/// burned code's row.
async fn recovery_depth_chain() {
    let k = Kit::new().await;
    let l = k.login().await;
    let (mut code, mut target) = (l.code.clone(), l.target.clone());
    for depth in 1..=3u32 {
        // the client presents no bind at all (cookie discarded), so every code mismatches
        let started = login_started(k.redeem(&code, &target, None, None).await);
        assert!(
            matches!(started.bind, BindAction::Plant(_)),
            "a fresh bind is offered each time"
        );
        let row = k
            .store
            .sessions()
            .transaction(&started.transaction.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.recovery_depth, depth, "burned code's depth + 1");
        let LoginEntry::Sso { location, .. } = k
            .svc
            .sso_or_chooser(
                &k.ctx(),
                &started.transaction,
                Some(&l.portal_handle),
                None,
                false,
            )
            .await
            .unwrap()
        else {
            panic!("expected Sso")
        };
        code = code_of(&location);
        target = strip_handoff(&location);
        assert_eq!(
            k.count(&format!(
                "SELECT recovery_depth FROM handoff_codes WHERE code_sha256 = x'{}'",
                code.digest()
            )),
            i64::from(depth),
            "the depth travels on the code"
        );
    }
    // depth 3 == handoff.max_recoveries: no transaction, the exhausted answer
    let txns = k.count("SELECT COUNT(*) FROM login_txns");
    match k.redeem(&code, &target, None, None).await {
        RedeemResult::Exhausted { depth } => assert_eq!(depth, 3),
        other => panic!("expected Exhausted, got {other:?}"),
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns"),
        txns,
        "no transaction is created"
    );
    let ev = k.events(EventKind::HandoffRejected).await;
    assert_eq!(ev.len(), 4);
    assert!(
        ev.iter()
            .any(|e| e.reason == Some(reasons::HANDOFF_RECOVERY_EXHAUSTED)
                && e.attrs.get("recovery_depth").and_then(|d| d.as_i64()) == Some(3))
    );
    // a fresh navigation without a code starts over at depth 0
    let fresh = k.start(APP, "/admin/x?a=1", None).await;
    assert_eq!(
        k.count(&format!(
            "SELECT recovery_depth FROM login_txns WHERE txn_sha256 = x'{}'",
            fresh.transaction.digest()
        )),
        0
    );
    // a browser that holds a valid handle is never in the recovery loop
    let hv = k.login().await;
    let (_, h, _, _) = minted(k.redeem(&hv.code, &hv.target, Some(&k.b1), None).await);
    let started = login_started(
        k.redeem(&random_token(&OsRng, 32), &hv.target, None, Some(&h))
            .await,
    );
    let row = k
        .store
        .sessions()
        .transaction(&started.transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.recovery_depth, 0);
}

// ---- abuse cases ------------------------------------------------------------

#[tokio::test]
async fn s003_a1_replayed_code_rejected() {
    let k = Kit::new().await;
    let l = k.login().await;
    let (_, h1, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let handles = k.count("SELECT COUNT(*) FROM session_handles");
    // the same request again, from a browser without H1
    let started = login_started(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    assert!(matches!(started.bind, BindAction::Keep));
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles"),
        handles,
        "no second handle"
    );
    assert_eq!(rejected_reasons(&k).await, vec!["code_consumed"]);
    // the existing session and handle are untouched
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions WHERE terminated_at IS NOT NULL"),
        0
    );
    assert!(
        k.store
            .sessions()
            .lookup_handle(&h1.digest(), &host(APP))
            .await
            .unwrap()
            .unwrap()
            .handle
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn s003_a2_moved_code_rejected_and_burned() {
    // another host (also registered): host mismatch
    let k = Kit::new().await;
    let l = k.login().await;
    let moved = url(&format!("https://{OTHER}/admin/x?a=1"));
    login_started(k.redeem(&l.code, &moved, Some(&k.b1), None).await);
    assert_eq!(rejected_reasons(&k).await, vec!["code_host_mismatch"]);
    // burned by the failed attempt: the right host cannot use it any more
    login_started(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    assert_eq!(
        rejected_reasons(&k).await,
        vec!["code_consumed", "code_host_mismatch"]
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE host != 'auth.example.test'"),
        0
    );

    // another path: path mismatch
    let k = Kit::new().await;
    let l = k.login().await;
    let other_path = url(&format!("https://{APP}/other"));
    login_started(k.redeem(&l.code, &other_path, Some(&k.b1), None).await);
    assert_eq!(rejected_reasons(&k).await, vec!["code_path_mismatch"]);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_reason='code_path_mismatch'"),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s003_a3_concurrent_redemption_single_handle() {
    let k = Kit::new().await;
    let l = k.login().await;
    let (a, b) = tokio::join!(
        k.redeem(&l.code, &l.target, Some(&k.b1), None),
        k.redeem(&l.code, &l.target, Some(&k.b1), None)
    );
    let outcomes = [a, b];
    let minted_n = outcomes
        .iter()
        .filter(|o| matches!(o, RedeemResult::Minted { .. }))
        .count();
    let login_n = outcomes
        .iter()
        .filter(|o| matches!(o, RedeemResult::Login(_)))
        .count();
    assert_eq!(
        (minted_n, login_n),
        (1, 1),
        "one 302 with a cookie, the other the portal redirect"
    );
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE host='{APP}'"
        )),
        1
    );
}

#[tokio::test]
async fn s003_a4_code_guessing_bounded() {
    let k = Kit::new().await;
    let target = url(&format!("https://{APP}/admin/x"));
    // ten wrong guesses from one IP are answered with the ordinary redirect
    for _ in 0..10 {
        let guess = random_token(&OsRng, 32);
        login_started(
            k.redeem_from("198.51.100.7", &guess, &target, Some(&k.b1), None)
                .await,
        );
    }
    assert_eq!(
        k.events(EventKind::HandoffRejected).await.len(),
        10,
        "every failure, unknown codes included, is recorded with the IP"
    );
    // the 11th is limited before anything is attempted
    let guess = random_token(&OsRng, 32);
    match k
        .redeem_from("198.51.100.7", &guess, &target, Some(&k.b1), None)
        .await
    {
        RedeemResult::RateLimited { retry_after } => {
            assert_eq!(retry_after, Duration::from_secs(60))
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
    // and a valid code from that IP is limited too (the limiter is per source address)
    // while another address is unaffected
    login_started(
        k.redeem_from(
            "198.51.100.8",
            &random_token(&OsRng, 32),
            &target,
            Some(&k.b1),
            None,
        )
        .await,
    );
    // the window slides
    k.advance(61);
    login_started(
        k.redeem_from(
            "198.51.100.7",
            &random_token(&OsRng, 32),
            &target,
            Some(&k.b1),
            None,
        )
        .await,
    );
    // digests are compared in constant time (crypto::ct_eq, tested by W0); a code is looked up by its digest only
    assert_eq!(k.count("SELECT COUNT(*) FROM handoff_codes"), 0);
}

#[tokio::test]
async fn s003_a6_portal_ignores_handoff_param() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.portal().get("/login?_hopae_handoff=K1");
    assert_eq!(r.status, 400, "no txn: the parameter is not consulted");
    let events = h.hooks.events(Some("handoff.rejected"), None);
    assert!(
        events.is_empty(),
        "the portal never tries to redeem: {events:?}"
    );
}

#[tokio::test]
async fn s003_a7_plain_http_target_refused() {
    let k = Kit::new().await;
    let l = k.login().await;
    // a transaction cannot be started, and a code cannot be redeemed, over
    // plain http while cookies are Secure: the engine refuses before it
    // touches the code (S003-A7: `insecure_transport`).
    let insecure = url(&format!("http://{APP}/admin/x?a=1"));
    for code in [None, Some(&l.code)] {
        let d = hopae::verify::decide(
            &k.verify,
            k.verify_input(IP, &insecure, code, Some(&k.b1), None),
        )
        .await;
        match d {
            hopae::verify::types::Decision::Deny { reason, .. } => {
                assert_eq!(reason.0, "insecure_transport")
            }
            _ => panic!("expected insecure_transport"),
        }
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE purpose='login'"),
        1,
        "only the kit's own login"
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_at IS NOT NULL"),
        0,
        "K1 not consumed"
    );
    // a later well-formed navigation succeeds
    minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
}

#[tokio::test]
async fn s003_a8_expired_code_uniform_response() {
    let k = Kit::new().await;
    let l = k.login().await;
    k.advance(61);
    let expired = login_started(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let unknown = login_started(
        k.redeem(&random_token(&OsRng, 32), &l.target, Some(&k.b1), None)
            .await,
    );
    // identical in everything the browser sees: the bind is kept and the
    // transaction is for the same target. Only the internal depth differs
    // (ADR-0014): the expired code is a known code on its first rejection, so
    // its depth carries (0 + 1); the unknown code starts at depth 0.
    assert!(matches!(expired.bind, BindAction::Keep) && matches!(unknown.bind, BindAction::Keep));
    assert_eq!(expired.app_id, unknown.app_id);
    let depth = |t: &Secret| {
        let d = t.digest();
        k.count(&format!(
            "SELECT recovery_depth FROM login_txns WHERE txn_sha256 = x'{d}'"
        ))
    };
    assert_eq!(
        (depth(&expired.transaction), depth(&unknown.transaction)),
        (1, 0)
    );
    // the distinction exists only in the events
    assert_eq!(
        rejected_reasons(&k).await,
        vec!["code_expired", "code_unknown"]
    );
}

pub(crate) struct Switching {
    pub v: Logged,
    pub hy: Secret,
    pub a: Logged,
    pub ts: Secret,
}

/// User V holds a valid application handle; the portal session now belongs to
/// user A, whose code reaches the application: `session_conflict`.
pub(crate) async fn switch_setup(k: &Kit) -> Switching {
    let v = k.login().await;
    let (_, hy, _, _) = minted(k.redeem(&v.code, &v.target, Some(&k.b1), None).await);
    k.mock
        .set_identity("sub-2", "b@example.test", true, false, "Bob");
    let a = k.login().await;
    assert_ne!(v.session_id, a.session_id);
    let RedeemResult::Switch { transaction } =
        k.redeem(&a.code, &a.target, Some(&k.b1), Some(&hy)).await
    else {
        panic!("expected Switch")
    };
    Switching {
        v,
        hy,
        a,
        ts: transaction,
    }
}

#[tokio::test]
async fn s003_a10_other_users_handle_requires_explicit_switch() {
    let k = Kit::new().await;
    let s = switch_setup(&k).await;
    // nothing was changed by the conflict: every cookie stays, the code is burned
    assert_eq!(
        k.count(&format!("SELECT COUNT(*) FROM handoff_codes WHERE code_sha256 = x'{}' AND consumed_reason='session_conflict'", s.a.code.digest())),
        1
    );
    assert_eq!(rejected_reasons(&k).await, vec!["session_conflict"]);
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
    // Ts: purpose switch, the other handle's digest, the clean target, A's session
    let ts = k
        .store
        .sessions()
        .transaction(&s.ts.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ts.purpose, hopae::store::types::TxnPurpose::Switch);
    assert_eq!(ts.conflicting_handle_sha256, Some(s.hy.digest()));
    assert_eq!(
        ts.return_target.as_str(),
        "https://app.example.test/admin/x?a=1"
    );
    assert_eq!(ts.portal_session_id.as_ref(), Some(&s.a.session_id));
    assert_eq!(ts.bind_sha256, Some(k.b1.digest()));

    // GET /switch shows host, user V and user A and changes nothing
    let view = k.svc.switch_view(&s.ts).await.unwrap();
    assert_eq!(view.host.as_str(), APP);
    assert_eq!(
        view.current
            .as_ref()
            .unwrap()
            .email
            .as_ref()
            .map(|e| e.as_str()),
        Some("a@example.test")
    );
    assert_eq!(
        view.incoming.email.as_ref().map(|e| e.as_str()),
        Some("b@example.test")
    );
    assert_eq!(
        k.count(
            "SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL AND purpose='switch'"
        ),
        0
    );

    // confirming needs the portal session of A, and only A
    let e = k
        .svc
        .switch_confirm(&k.ctx(), &s.ts, SwitchChoice::Switch, None)
        .await
        .unwrap_err();
    assert_eq!(e.reason().0, "login_required");
    let e = k
        .svc
        .switch_confirm(
            &k.ctx(),
            &s.ts,
            SwitchChoice::Switch,
            Some(&s.v.portal_handle),
        )
        .await
        .unwrap_err();
    assert_eq!(
        e.reason().0,
        "session_conflict",
        "V's portal handle cannot confirm A's switch"
    );
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

    // choice=switch with A's portal handle: Hy revoked (reason switch), a fresh code for A bound to By
    let out = k
        .svc
        .switch_confirm(
            &k.ctx(),
            &s.ts,
            SwitchChoice::Switch,
            Some(&s.a.portal_handle),
        )
        .await
        .unwrap();
    let SwitchOutcome::Switched { location } = out else {
        panic!("expected Switched")
    };
    assert_eq!(
        strip_handoff(&location).as_str(),
        "https://app.example.test/admin/x?a=1"
    );
    let new_code = code_of(&location);
    assert_eq!(
        k.count(&format!("SELECT COUNT(*) FROM handoff_codes WHERE code_sha256 = x'{}' AND session_id='{}' AND bind_sha256 = x'{}' AND consumed_at IS NULL", new_code.digest(), s.a.session_id, k.b1.digest())),
        1
    );
    let old = k
        .store
        .sessions()
        .lookup_handle(&s.hy.digest(), &host(APP))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.handle.revoked_reason.as_deref(), Some("switch"));
    assert!(
        old.session.terminated_at.is_none(),
        "V's session is otherwise untouched"
    );
    let revoked = k.events(EventKind::HandleRevoked).await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].reason, Some(reasons::SWITCH));
    // single use
    let again = k
        .svc
        .switch_confirm(
            &k.ctx(),
            &s.ts,
            SwitchChoice::Switch,
            Some(&s.a.portal_handle),
        )
        .await
        .unwrap_err();
    assert_eq!(again.reason().0, "txn_consumed");
    // the next verify plants A's handle (the browser still sends the revoked Hy)
    let (_, ha, _, _) = minted(
        k.redeem(&new_code, &s.a.target, Some(&k.b1), Some(&s.hy))
            .await,
    );
    let view = k
        .store
        .sessions()
        .lookup_handle(&ha.digest(), &host(APP))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.session.session_id, s.a.session_id);

    // choice=keep: back to the clean target as the existing user, nothing revoked
    let k = Kit::new().await;
    let s = switch_setup(&k).await;
    let out = k
        .svc
        .switch_confirm(&k.ctx(), &s.ts, SwitchChoice::Keep, None)
        .await
        .unwrap();
    let SwitchOutcome::Kept { location } = out else {
        panic!("expected Kept")
    };
    assert_eq!(location.as_str(), "https://app.example.test/admin/x?a=1");
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

    // Hy belonging to A's own session: the code is redeemed directly and Hy is replaced
    let k = Kit::new().await;
    let l = k.login().await;
    let (_, hy, _, _) = minted(k.redeem(&l.code, &l.target, Some(&k.b1), None).await);
    let t2 = k.start(APP, "/admin/x?a=1", Some(&k.b1)).await;
    let LoginEntry::Sso { location, .. } = k
        .svc
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&l.portal_handle),
            None,
            false,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let (_, hy2, _, _) = minted(
        k.redeem(
            &code_of(&location),
            &strip_handoff(&location),
            Some(&k.b1),
            Some(&hy),
        )
        .await,
    );
    assert_ne!(hy.digest(), hy2.digest());
    assert_eq!(
        k.store
            .sessions()
            .lookup_handle(&hy.digest(), &host(APP))
            .await
            .unwrap()
            .unwrap()
            .handle
            .revoked_reason
            .as_deref(),
        Some("replaced")
    );
}

/// A stolen portal handle yields a code for the attacker's bind on the other host.
async fn sso_to_other(k: &Kit, bx: &Secret, portal: &Secret) -> (Secret, Url) {
    let t = k.start(OTHER, "/", Some(bx)).await;
    let ctx = k.ctx();
    let LoginEntry::Sso { location, .. } = k
        .svc
        .sso_or_chooser(&ctx, &t.transaction, Some(portal), None, false)
        .await
        .unwrap()
    else {
        panic!("expected Sso")
    };
    (code_of(&location), strip_handoff(&location))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s003_a11_pre_elevation_code_never_elevated() {
    let bx = fresh_bind();
    // a stolen portal handle yields K0 for the attacker's bind Bx on the other host
    // (a) the elevation committed first: no handle, K0 was consumed by the elevation
    let k = Kit::new().await;
    let l = k.login().await;
    let (k0, target) = sso_to_other(&k, &bx, &l.portal_handle).await;
    k.elevate(l.session_id.as_str());
    login_started(k.redeem(&k0, &target, Some(&bx), None).await);
    assert_eq!(rejected_reasons(&k).await, vec!["code_consumed"]);
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE host='{OTHER}'"
        )),
        0
    );

    // (b) the redemption committed first: a level-1 handle that the elevation then revokes
    let k = Kit::new().await;
    let l = k.login().await;
    let (k0, target) = sso_to_other(&k, &bx, &l.portal_handle).await;
    let (_, h, aal, _) = minted(k.redeem(&k0, &target, Some(&bx), None).await);
    assert_eq!(aal, Aal::One, "min(1, 1)");
    k.elevate(l.session_id.as_str());
    let view = k
        .store
        .sessions()
        .lookup_handle(&h.digest(), &host(OTHER))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.handle.issued_aal, Aal::One);
    assert_eq!(view.handle.revoked_reason.as_deref(), Some("elevation"));
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE issued_aal = 2"),
        0
    );

    // 60 unordered races: in no interleaving does an elevated or a live handle result
    let k = Kit::with(Opts {
        txn_per_ip: 10_000,
        failures_per_minute: 10_000,
        ..Opts::default()
    })
    .await;
    for i in 0..60 {
        let l = k.login().await;
        let (k0, target) = sso_to_other(&k, &bx, &l.portal_handle).await;
        let sid = l.session_id.clone();
        let (r, ()) = tokio::join!(k.redeem(&k0, &target, Some(&bx), None), async {
            if i % 2 == 0 {
                tokio::task::yield_now().await;
            }
            k.elevate(sid.as_str());
        });
        if let RedeemResult::Minted { issued_aal, .. } = r {
            assert_eq!(issued_aal, Aal::One, "iteration {i}");
        }
        assert_eq!(
            k.count(&format!("SELECT COUNT(*) FROM session_handles WHERE session_id='{sid}' AND host='{OTHER}' AND revoked_at IS NULL")),
            0,
            "iteration {i}: the attacker's handle does not survive the elevation"
        );
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM session_handles WHERE issued_aal = 2"),
        0
    );
}

#[tokio::test]
async fn s003_a12_ambiguous_parameter_refused() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    for q in [
        "?_hopae_handoff=K1&_hopae_handoff=K2",
        "?_hopae_handoff=K1&%5Fhopae%5Fhandoff=K1",
        "?%5Fhopae%ZZhandoff=K1",
    ] {
        let r = h.verify(
            VerifyRequest::document(&format!("https://app.example.test/admin/x{q}"))
                .ip("203.0.113.9")
                .cookie("__Host-hopae_bind", "AAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert_eq!(r.status, 403, "{q}");
        assert_eq!(r.header("x-hopae-reason"), Some("handoff_ambiguous"), "{q}");
        assert!(r.set_cookies().is_empty(), "no cookie changes: {q}");
    }
    let rejected = h.hooks.events(Some("handoff.rejected"), None);
    assert!(rejected.iter().all(|e| e["reason"] == "handoff_ambiguous") && rejected.len() == 3);
    // TODO(W2-A): with an HTTP login helper, also assert that a real K1 stays
    // unconsumed and that the later well-formed navigation redeems it.
}

// ---- gateway layer (W2-A) ---------------------------------------------------
//
// The cases below run through the real gateway binary (`HOPAE_E2E_GATEWAY_BINARY`,
// `make e2e`); without the variable they skip.

mod gateway_layer {
    use crate::support::gateway::*;
    use crate::support::*;

    fn two_domains(test: &str) -> Option<Stack> {
        Stack::start(
            test,
            Fixture::new("m1-two-domains"),
            GatewayRoutes::new()
                .whole_host(APP_HOST)
                .whole_host(OTHER_HOST)
                .portal(PORTAL_HOST),
            Edge::Terminator,
        )
    }

    fn rejected_reasons(s: &Stack) -> Vec<String> {
        s.hopae
            .hooks
            .events(Some("handoff.rejected"), None)
            .iter()
            .map(|e| e["reason"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    fn has_bind(b: &Browser, host: &str) -> Option<String> {
        b.jar.for_host(host).value("__Host-hopae_bind")
    }

    fn handle_of(b: &Browser, host: &str) -> Option<String> {
        b.jar.for_host(host).value("__Host-hopae")
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s003_5_handoff_through_live_gateway() {
        let Some(s) = two_domains("s003_5") else {
            return;
        };
        let b = s.gw.browser();
        // First application: login, handoff, final 200.
        let first = b.get(APP_HOST, "/admin/x");
        assert_eq!(first.status, 302);
        assert_eq!(
            first.header("referrer-policy"),
            Some("no-referrer"),
            "present on the relayed 302"
        );
        let c1 = b.login_from(&s.idp, first);
        let code1 = c1.code();
        let handoff1 = b.redeem(&c1);
        assert_eq!(handoff1.status, 302, "{handoff1:?}");
        assert_eq!(
            handoff1.location(),
            Some("https://app.example.test/admin/x")
        );
        assert_eq!(handoff1.header("referrer-policy"), Some("no-referrer"));
        assert!(
            handoff1
                .set_cookies()
                .iter()
                .any(|c| c.starts_with("__Host-hopae=")),
            "the handle is planted by the relayed 302"
        );
        let r1 = b.follow(APP_HOST, &handoff1);
        assert_eq!(r1.status, 200, "{r1:?}");
        assert_eq!(r1.body, "echo /admin/x\n");

        // Second application on another registrable domain: single sign-on.
        let first2 = b.get(OTHER_HOST, "/");
        assert_eq!(first2.status, 302);
        assert_eq!(first2.header("referrer-policy"), Some("no-referrer"));
        assert!(
            first2
                .set_cookies()
                .iter()
                .any(|c| c.starts_with("__Host-hopae_bind=")),
            "the binding cookie is planted on the second host"
        );
        let c2 = b.sso_to_code(first2);
        let code2 = c2.code();
        let handoff2 = b.redeem(&c2);
        assert_eq!(handoff2.status, 302, "{handoff2:?}");
        assert_eq!(handoff2.location(), Some("https://other.example.org/"));
        assert_eq!(handoff2.header("referrer-policy"), Some("no-referrer"));
        let r2 = b.follow(OTHER_HOST, &handoff2);
        assert_eq!(r2.status, 200, "{r2:?}");

        // Cookies exist per host only, and differ.
        let (h_app, h_other) = (handle_of(&b, APP_HOST), handle_of(&b, OTHER_HOST));
        assert!(h_app.is_some() && h_other.is_some());
        assert_ne!(h_app, h_other);
        assert_ne!(
            h_app,
            handle_of(&b, PORTAL_HOST),
            "the portal session has its own handle"
        );
        for (host, resp) in [(APP_HOST, &handoff1), (OTHER_HOST, &handoff2)] {
            let own = b.jar.for_host(host).names();
            assert!(own.contains(&"__Host-hopae".to_string()), "{host}: {own:?}");
            assert!(
                resp.set_cookies().iter().all(|c| !c.contains("Domain=")),
                "host-only cookies"
            );
        }

        // The upstream never received a code, in any form.
        let seen = s.echo.requests();
        assert!(seen.len() >= 2);
        for r in &seen {
            assert!(!r.raw_path.contains("_hopae_handoff"), "{r:?}");
            for (_, v) in &r.headers {
                assert!(!v.contains(&code1) && !v.contains(&code2), "{r:?}");
            }
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s003_7_non_document_with_parameter_terminated() {
        let Some(s) = Stack::basic("s003_7") else {
            return;
        };
        let b = s.gw.browser();
        let c1 = b.login_to_code(&s.idp, APP_HOST, "/admin/x");
        let (k1, pq1) = (c1.code(), c1.path_and_query());
        let bind = has_bind(&b, APP_HOST).expect("B1 held");
        let unconsumed = |s: &Stack| code_row(&s.hopae, &k1).expect("K1 row").0.is_none();
        assert!(unconsumed(&s));
        s.echo.clear();
        s.gw.tap.clear();

        let expect_terminated = |s: &Stack, b: &Browser, pq: &str, what: &str| {
            let before = s.gw.tap.answers().len();
            let r = b.fetch(APP_HOST, pq);
            assert_eq!(r.status, 403, "{what}: {r:?}");
            assert_eq!(
                r.body.trim(),
                r#"{"error":"handoff_parameter_not_allowed"}"#,
                "{what}"
            );
            assert!(r.set_cookies().is_empty(), "{what}: no set-cookie");
            let answers = s.gw.tap.answers();
            assert_eq!(answers.len(), before + 1);
            let a = answers.last().unwrap();
            assert_eq!(a.status, 403);
            assert_eq!(
                a.header("x-hopae-reason"),
                Some("handoff_parameter_not_allowed"),
                "{what}"
            );
            assert!(
                s.echo.requests().is_empty(),
                "{what}: the gateway forwarded the query"
            );
        };

        // (1) no handle
        expect_terminated(&s, &b, &pq1, "without a handle");
        assert!(unconsumed(&s), "K1 stays unconsumed");
        assert_eq!(has_bind(&b, APP_HOST).as_deref(), Some(bind.as_str()));

        // Another tab finishes first: a valid handle H1 for the same session.
        let first = b.get(APP_HOST, "/admin/y");
        assert_eq!(first.status, 302);
        let c2 = b.sso_to_code(first);
        let planted = b.redeem(&c2);
        assert_eq!(planted.status, 302, "{planted:?}");
        let h1 = handle_of(&b, APP_HOST).expect("H1");
        assert!(unconsumed(&s));
        s.echo.clear();

        // (2) valid handle + K1, (3) valid handle + an invalid code: still 403,
        // never a 200 that would make the gateway forward the query.
        expect_terminated(&s, &b, &pq1, "valid handle and K1");
        expect_terminated(
            &s,
            &b,
            "/admin/x?_hopae_handoff=bogus-code-value",
            "valid handle, invalid code",
        );
        assert!(unconsumed(&s), "K1 stays unconsumed");
        assert_eq!(
            handle_of(&b, APP_HOST).as_deref(),
            Some(h1.as_str()),
            "H1 untouched"
        );
        assert_eq!(
            has_bind(&b, APP_HOST).as_deref(),
            Some(bind.as_str()),
            "B1 untouched"
        );

        // The user's later document navigation with K1 succeeds (same session, so
        // the handle is replaced) and reaches the clean URL.
        let later = b.get_cross_site(APP_HOST, &pq1);
        assert_eq!(later.status, 302, "{later:?}");
        assert_eq!(later.location(), Some("https://app.example.test/admin/x"));
        assert!(!unconsumed(&s), "K1 is consumed by the document navigation");
        assert!(s.echo.requests().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s003_a5_upstream_never_sees_code() {
        let Some(s) = two_domains("s003_a5") else {
            return;
        };
        let b = s.gw.browser();
        let c = b.login_to_code(&s.idp, APP_HOST, "/admin/x");
        let code = c.code();
        // A second code for the same session, which is the one a compromised
        // application could construct a URL for on another host.
        let c_other = b.sso_to_code(b.get(APP_HOST, "/admin/x"));
        let stolen_code = c_other.code();
        let stolen = b.fetch(OTHER_HOST, &format!("/?_hopae_handoff={stolen_code}"));
        assert_eq!(
            stolen.status, 403,
            "non-document: terminated at the gateway"
        );
        let stolen = b.get_cross_site(OTHER_HOST, &format!("/?_hopae_handoff={stolen_code}"));
        assert_eq!(
            stolen.status, 302,
            "document: unauthenticated, to the portal: {stolen:?}"
        );
        assert!(stolen.location().unwrap().contains("/login?txn="));
        assert!(
            handle_of(&b, OTHER_HOST).is_none(),
            "no handle for the other host"
        );
        assert!(
            stolen
                .set_cookies()
                .iter()
                .all(|c| !c.starts_with("__Host-hopae=")),
            "{stolen:?}"
        );
        assert_eq!(
            code_row(&s.hopae, &stolen_code).unwrap().0.as_deref(),
            Some("code_host_mismatch"),
            "burned"
        );
        // Whatever Hopae decided, the upstream saw nothing.
        assert!(s.echo.requests().is_empty(), "{:?}", s.echo.requests());
        // The legitimate redemption never forwards the code either.
        let handoff = b.redeem(&c);
        assert_eq!(handoff.status, 302, "{handoff:?}");
        let after = b.follow(APP_HOST, &handoff);
        assert_eq!(after.status, 200, "{after:?}");
        for r in s.echo.requests() {
            assert!(!r.raw_path.contains("_hopae_handoff"));
            for (_, v) in &r.headers {
                assert!(
                    !v.contains(&code) && !v.contains(&stolen_code),
                    "a code reached the upstream in a header"
                );
            }
        }
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s003_a9_two_browsers_same_ip_cannot_swap_sessions() {
        let Some(s) = Stack::basic("s003_a9") else {
            return;
        };
        let nat = "203.0.113.9";
        let x = s.gw.browser().at_ip(nat);

        // (a) X completed a login and captured its unconsumed code Kx; Y holds no
        // cookie on the application host.
        let kx = x.login_to_code(&s.idp, APP_HOST, "/admin/x");
        let y = s.gw.browser().at_ip(nat);
        let taken = y.get_cross_site(APP_HOST, &kx.path_and_query());
        assert_eq!(taken.status, 302, "{taken:?}");
        assert!(
            taken.location().unwrap().contains("/login?txn="),
            "{taken:?}"
        );
        assert!(
            taken
                .set_cookies()
                .iter()
                .all(|c| !c.starts_with("__Host-hopae=")),
            "no handle for Y"
        );
        assert!(handle_of(&y, APP_HOST).is_none());
        // Y had none, so a fresh binding cookie is planted.
        assert!(has_bind(&y, APP_HOST).is_some());
        assert_eq!(
            code_row(&s.hopae, &kx.code()).unwrap().0.as_deref(),
            Some("bind_mismatch")
        );
        assert!(rejected_reasons(&s).contains(&"bind_mismatch".to_string()));
        // X's own later navigation with Kx is refused; X recovers by single sign-on.
        let again = x.redeem(&kx);
        assert_eq!(again.status, 302, "{again:?}");
        assert!(again.location().unwrap().contains("/login?txn="));
        assert!(
            again
                .set_cookies()
                .iter()
                .all(|c| !c.starts_with("__Host-hopae=")),
            "the replay yields no handle"
        );
        assert!(
            rejected_reasons(&s).contains(&"code_consumed".to_string()),
            "{:?}",
            rejected_reasons(&s)
        );
        let recovered = x.sso_to_code(again);
        let ok = x.redeem(&recovered);
        assert_eq!(ok.status, 302, "{ok:?}");
        assert_eq!(x.follow(APP_HOST, &ok).status, 200);

        // (b) Y holds its own binding cookie By from a login it started.
        x.jar.for_host(APP_HOST).remove("__Host-hopae");
        let y = s.gw.browser().at_ip(nat);
        let started = y.get(APP_HOST, "/admin/x");
        assert_eq!(started.status, 302);
        let by = has_bind(&y, APP_HOST).expect("By");
        let kx2 = x.sso_to_code(x.get(APP_HOST, "/admin/x3"));
        let taken = y.get_cross_site(APP_HOST, &kx2.path_and_query());
        assert_eq!(taken.status, 302, "{taken:?}");
        assert!(taken.location().unwrap().contains("/login?txn="));
        assert_eq!(
            has_bind(&y, APP_HOST).as_deref(),
            Some(by.as_str()),
            "By kept"
        );
        assert!(
            taken
                .set_cookies()
                .iter()
                .all(|c| !c.starts_with("__Host-hopae="))
        );
        assert!(handle_of(&y, APP_HOST).is_none());

        // The code is burned by the failed attempt.
        assert_eq!(
            code_row(&s.hopae, &kx2.code()).unwrap().0.as_deref(),
            Some("bind_mismatch")
        );
        assert!(
            s.echo
                .requests()
                .iter()
                .all(|r| !r.raw_path.contains("_hopae_handoff"))
        );
    }

    /// The recovery chain of S003-A13 for a client whose jar drops the binding
    /// cookie before every request. Returns the final response and the last
    /// code (the burned one) navigated.
    fn chase_without_bind(s: &Stack, b: &Browser) -> (Response, LastCode) {
        let mut r = b.get(APP_HOST, "/admin/x");
        let mut last = LastCode(String::new());
        for _ in 0..8 {
            assert_eq!(r.status, 302, "{r:?}");
            b.jar.for_host(APP_HOST).remove("__Host-hopae_bind");
            let c = b.sso_to_code(r);
            last = LastCode(c.path_and_query());
            r = b.redeem(&c);
            b.jar.for_host(APP_HOST).remove("__Host-hopae_bind");
            if r.status != 302 {
                break;
            }
        }
        let _ = s;
        (r, last)
    }

    pub struct LastCode(pub String);

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn s003_a13_recovery_bounded_no_upstream() {
        let Some(s) = Stack::basic("s003_a13") else {
            return;
        };
        let b = s.gw.browser();
        // The portal holds a valid H0 after one ordinary login; then the
        // application cookies are dropped.
        let l = b.login(&s.idp, APP_HOST, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        let cookies = b.jar.for_host(APP_HOST);
        cookies.remove("__Host-hopae");
        cookies.remove("__Host-hopae_bind");
        s.echo.clear();
        s.gw.tap.clear();
        let before_txns = txn_depths(&s.hopae).len();

        // Run 1: a jar that discards every binding cookie.
        let (end, last) = chase_without_bind(&s, &b);
        assert_eq!(end.status, 403, "exhaustion is never a 2xx: {end:?}");
        assert_eq!(
            end.header("content-type")
                .map(|c| c.starts_with("text/html")),
            Some(true)
        );
        assert_eq!(end.header("cache-control"), Some("no-store"));
        let answer = s.gw.tap.answers().last().cloned().unwrap();
        assert_eq!(answer.status, 403);
        assert_eq!(
            answer.header("x-hopae-reason"),
            Some("handoff_recovery_exhausted")
        );
        assert!(
            s.echo.requests().is_empty(),
            "zero upstream requests during the whole chain"
        );
        let depths = txn_depths(&s.hopae);
        assert_eq!(
            &depths[before_txns..],
            &[0, 1, 2, 3],
            "depth is the burned code's depth plus one; the fourth mismatch creates no transaction"
        );
        assert!(
            s.hopae
                .hooks
                .events(Some("handoff.rejected"), None)
                .iter()
                .any(|e| e["reason"] == "handoff_recovery_exhausted"),
            "the event records the exhaustion"
        );
        // A crafted depth anywhere has no effect: a fresh navigation starts at depth 0.
        let fresh = b.fresh().get(APP_HOST, "/admin/x?depth=3");
        assert_eq!(fresh.status, 302);
        assert_eq!(*txn_depths(&s.hopae).last().unwrap(), 0);

        // Run 3 (before run 2: it needs the burned code): replaying the burned
        // depth-3 code from other browsers restarts at depth 0 and never reaches
        // the exhaustion page.
        for i in 0..3 {
            let other = s.gw.browser().at_ip(&format!("198.51.100.{}", 20 + i));
            let r = other.get_cross_site(APP_HOST, &last.0);
            assert_eq!(r.status, 302, "replay {i}: {r:?}");
            assert!(r.location().unwrap().contains("/login?txn="));
            assert_eq!(
                *txn_depths(&s.hopae).last().unwrap(),
                0,
                "a consumed code restarts at depth 0"
            );
        }
        assert!(s.echo.requests().is_empty());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn gateway_s003_a13_ip_mismatch_recovery_bounded() {
        // The right binding cookie, but a client address that differs on every
        // redemption (code_ip_mismatch). The `open` application of m1-binding (and the
        // `default` policy that governs the portal session) have `binding.ip: off`, so
        // the portal itself accepts the changing address and the code's recorded
        // address is what stops the redemption.
        const OPEN: &str = "open.example.test";
        let Some(s) = Stack::start(
            "s003_a13_ip",
            // the portal session is evaluated with the `default` application's binding
            Fixture::with(
                "m1-binding",
                serde_json::json!({"apps": [{"app_id": "default", "binding": {"ip": "off"}}]}),
            ),
            GatewayRoutes::new().whole_host(OPEN).portal(PORTAL_HOST),
            Edge::Terminator,
        ) else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, OPEN, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        b.jar.for_host(OPEN).remove("__Host-hopae");
        s.echo.clear();
        s.gw.tap.clear();
        let before = txn_depths(&s.hopae).len();
        let ip = |n: u32| format!("198.51.100.{n}");
        let mut n = 1;
        let mut r = b.at_ip(&ip(n)).get(OPEN, "/admin/x");
        let mut end = None;
        for _ in 0..8 {
            assert_eq!(r.status, 302, "{r:?}");
            let c = b.at_ip(&ip(n)).sso_to_code(r);
            n += 1;
            r = b.at_ip(&ip(n)).redeem(&c);
            if r.status != 302 {
                end = Some(r);
                break;
            }
        }
        let end = end.expect("the chain ends");
        assert_eq!(end.status, 403, "{end:?}");
        assert_eq!(
            s.gw.tap.answers().last().unwrap().header("x-hopae-reason"),
            Some("handoff_recovery_exhausted")
        );
        assert!(s.echo.requests().is_empty());
        assert_eq!(
            &txn_depths(&s.hopae)[before..],
            &[0, 1, 2, 3],
            "same number of round trips"
        );
        assert!(
            s.hopae
                .hooks
                .events(Some("handoff.rejected"), None)
                .iter()
                .any(|e| e["reason"] == "code_ip_mismatch")
        );
    }
}
