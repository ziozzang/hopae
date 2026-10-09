//! Handoff redemption (ADR-0004): a document navigation that carries
//! `_hopae_handoff=<code>` is answered here. The atomic conditional update
//! lives in the store; this module prepares the request, classifies the
//! outcome and turns it into a [`Decision`].

use std::time::Duration;

use url::Url;

use super::engine::{self, Cx, Flow};
use super::types::*;
use crate::crypto::{Secret, handle_value, is_well_formed_bind, sha256};
use crate::event::types::{EventKind, Outcome, reasons};
use crate::policy::types::AppPolicy;
use crate::session::types::SessionId;
use crate::store::types::{HandleRow, NewTransaction, RedeemOutcome, RedeemRequest, TxnPurpose};

/// The reserved query parameter (ADR-0004).
pub const HANDOFF_PARAM: &str = "_hopae_handoff";

/// One query pair is the handoff parameter when its percent-decoded name
/// (with `+` as a space) is exactly the reserved name.
fn is_handoff_pair(pair: &str) -> bool {
    let name = pair.split_once('=').map_or(pair, |(n, _)| n);
    let spaced = name.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced).decode_utf8_lossy() == HANDOFF_PARAM
}

/// The URL without any handoff pair: other pairs keep their order and their
/// bytes, and an emptied query disappears (no trailing `?`).
pub fn clean_target(url: &Url) -> Url {
    let Some(query) = url.query() else {
        return url.clone();
    };
    let kept: Vec<&str> = query.split('&').filter(|p| !is_handoff_pair(p)).collect();
    let mut out = url.clone();
    if kept.iter().all(|p| p.is_empty()) {
        out.set_query(None);
    } else {
        out.set_query(Some(&kept.join("&")));
    }
    out
}

/// Redeem `code` for the browser behind this request.
pub(super) async fn redeem(cx: &Cx<'_>, app: &AppPolicy, target: &Url, code: &Secret) -> Flow {
    let (ctx, input) = (cx.ctx, cx.input);
    let clean = clean_target(target);

    let window = Duration::from_secs(60);
    let failures = ctx
        .sessions
        .count_handoff_failures_since(input.client_ip, cx.now.sub(window))
        .await
        .map_err(|e| cx.store_err(e))?;
    if failures >= engine::HANDOFF_FAILURES_PER_MINUTE {
        return Err(cx.deny(
            reasons::RATE_LIMITED,
            DenyKind::RateLimited {
                retry_after: window,
            },
        ));
    }

    let presented_bind = input
        .bind_cookie
        .as_ref()
        .filter(|b| is_well_formed_bind(b.expose()));
    let presented = cx.live_presented_handle(app).await?;

    let new_secret = handle_value(&*ctx.rng);
    let new_handle = HandleRow {
        handle_sha256: new_secret.digest(),
        // The store completes the session from the code row (W0 request R1).
        session_id: SessionId::new(String::new()),
        host: input.host.clone(),
        issued_aal: crate::session::types::Aal::One,
        created_at: cx.now,
        last_seen_at: cx.now,
        absolute_expires_at: cx.now.add(app.session.absolute),
        revoked_at: None,
        revoked_reason: None,
    };
    let ok = cx
        .event(EventKind::SessionHandoff, Outcome::Success, app)
        .attr("host", input.host.as_str())
        .build();
    let fail = cx
        .event(EventKind::HandoffRejected, Outcome::Failure, app)
        .attr("host", input.host.as_str())
        .build();
    let req = RedeemRequest {
        code_sha256: code.digest(),
        host: input.host.clone(),
        path: target.path().to_string(),
        client_ip: input.client_ip,
        presented_bind_sha256: presented_bind.map(Secret::digest),
        presented_handle: presented.clone(),
        new_handle,
        now: cx.now,
    };
    let outcome = ctx
        .sessions
        .redeem_handoff_code(req, vec![ok], vec![fail])
        .await
        .map_err(|e| cx.store_err(e))?;

    match outcome {
        RedeemOutcome::Minted { issued_aal, .. } => Ok(Decision::Handoff {
            location: clean,
            handle: new_secret,
            issued_aal,
            max_age: app.session.absolute,
        }),
        RedeemOutcome::AlreadyRedeemed => Ok(Decision::CleanRedirect { location: clean }),
        RedeemOutcome::SessionConflict { code } => {
            let conflicting = presented.map(|v| v.handle.handle_sha256);
            let (bind_digest, _) = cx.bind_for_transaction();
            let txn = crate::crypto::random_token(&*cx.ctx.rng, 16);
            let row = NewTransaction {
                txn_sha256: txn.digest(),
                created_at: cx.now,
                expires_at: cx.now.add(engine::TXN_TTL),
                app_id: app.app_id.clone(),
                return_target: clean,
                bind_sha256: Some(bind_digest),
                portal_bind_sha256: None,
                retry_bind_sha256: None,
                client_ip: input.client_ip,
                ua_sha256: input.user_agent.as_deref().map(|u| sha256(u.as_bytes())),
                provider_id: None,
                state_sha256: None,
                nonce: None,
                pkce_verifier: None,
                // The session the portal switches to when the user confirms.
                portal_session_id: Some(code.session_id.clone()),
                purpose: TxnPurpose::Switch,
                conflicting_handle_sha256: conflicting,
                pending_identity: None,
                recovery_depth: code.recovery_depth,
            };
            ctx.sessions
                .create_transaction(row, vec![])
                .await
                .map_err(|e| cx.store_err(e))?;
            Ok(Decision::Switch { transaction: txn })
        }
        RedeemOutcome::Exhausted { .. } => {
            Err(cx.deny(reasons::HANDOFF_RECOVERY_EXHAUSTED, DenyKind::ForbiddenHtml))
        }
        RedeemOutcome::Rejected { reason, code } => {
            // First-use race between tabs: the bind cookie differs and the
            // browser holds no valid handle. Recover through the portal, at
            // depth + 1, until the configured bound (depth is read only from
            // the burned code's row, never from the client).
            let race = reason == reasons::BIND_MISMATCH && presented.is_none();
            let depth = match (race, &code) {
                (true, Some(c)) => {
                    if c.recovery_depth >= ctx.limits.max_recoveries {
                        return Err(
                            cx.deny(reasons::HANDOFF_RECOVERY_EXHAUSTED, DenyKind::ForbiddenHtml)
                        );
                    }
                    c.recovery_depth + 1
                }
                _ => 0,
            };
            engine::login(cx, app, &clean, false, depth).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use super::*;
    use crate::crypto::{Clock, SeededRng, TestClock, Timestamp, random_id, random_token};
    use crate::identity::types::NormalizedEmail;
    use crate::policy::types::Host;
    use crate::provider::types::ProviderId;
    use crate::session::types::{Aal, FactorEntry, FactorKind};
    use crate::store::types::*;
    use crate::store::{Store, StoreHooks};

    const T0: i64 = 1_800_000_000_000;
    const URL: &str = "https://app.example.test/admin/x?q=1";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    struct T {
        _dir: tempfile::TempDir,
        store: Store,
        clock: Arc<TestClock>,
        rng: Arc<SeededRng>,
        ctx: VerifyContext,
    }

    struct Code {
        secret: Secret,
        bind: Secret,
        session: SessionRow,
    }

    fn t() -> T {
        let cfg = crate::config::parse(
            r#"{"listen":{"portal":"127.0.0.1:0","gateway":"127.0.0.1:0"},
                "state_dir":"state","portal":{"public_url":"https://auth.example.test"},
                "gateway":{"kind":"hangang","caller_key_env":"K"},
                "apps":[{"app_id":"app","hosts":["app.example.test"]}],
                "handoff":{"max_recoveries":3}}"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(T0)));
        let store = Store::open(
            &dir.path().join("hopae.db"),
            clock.clone(),
            vec!["log".into()],
            Some(Arc::new(StoreHooks::new())),
        )
        .unwrap();
        let rng = Arc::new(SeededRng::new(5));
        store.set_rng(rng.clone());
        let ctx = VerifyContext::new(
            store.directory(),
            store.sessions(),
            clock.clone(),
            rng.clone(),
            Arc::new(ArcSwap::from_pointee(cfg.snapshot(5))),
            cfg.verify_limits(),
        );
        T {
            _dir: dir,
            store,
            clock,
            rng,
            ctx,
        }
    }

    impl T {
        async fn user(&self, n: u32) -> User {
            let email = NormalizedEmail::parse(&format!("user{n}@example.test")).unwrap();
            self.store
                .directory()
                .create_user(
                    NewUser {
                        primary_email: Some(email.clone()),
                        email_verified: true,
                        email_authoritative: false,
                        display_name: None,
                        username: Some(format!("user{n}")),
                    },
                    NewIdentity {
                        provider_id: ProviderId::new("mock"),
                        subject: format!("sub-{n}"),
                        email: Some(email),
                        email_verified: true,
                        email_authoritative: false,
                        name: None,
                        picture: None,
                        raw_claims: serde_json::json!({}),
                    },
                    vec![],
                )
                .await
                .unwrap()
        }

        fn handle_row(&self, s: &SessionRow, host: &str, secret: &Secret) -> HandleRow {
            let now = self.clock.now();
            HandleRow {
                handle_sha256: secret.digest(),
                session_id: s.session_id.clone(),
                host: Host::parse(host).unwrap(),
                issued_aal: Aal::One,
                created_at: now,
                last_seen_at: now,
                absolute_expires_at: now.add(Duration::from_secs(7 * 86400)),
                revoked_at: None,
                revoked_reason: None,
            }
        }

        async fn session(&self, user: &User) -> (SessionRow, Secret) {
            let now = self.clock.now();
            let row = SessionRow {
                session_id: SessionId::new(random_id(&*self.rng, "s_")),
                user_id: user.user_id.clone(),
                provider_id: ProviderId::new("mock"),
                auth_time: now,
                factors: vec![FactorEntry {
                    kind: FactorKind::Oidc,
                    provider: None,
                    at: now,
                }],
                aal: Aal::One,
                authz_version: user.authz_version,
                cred_gen: 1,
                snapshot: IdentitySnapshot {
                    email: user.primary_email.clone(),
                    display_name: None,
                    username: user.username.clone(),
                    groups: vec![],
                },
                bound_ip: ip("203.0.113.9"),
                bound_ua_sha256: None,
                created_at: now,
                last_seen_at: now,
                absolute_expires_at: now.add(Duration::from_secs(30 * 86400)),
                terminated_at: None,
                terminated_reason: None,
            };
            let portal = handle_value(&*self.rng);
            let h = self.handle_row(&row, "auth.example.test", &portal);
            let digest = h.handle_sha256;
            self.store
                .sessions()
                .create_session(CreateSession {
                    session: row.clone(),
                    portal_handle: h,
                    portal_handle_digest: digest,
                    events: vec![],
                })
                .await
                .unwrap();
            (row, portal)
        }

        async fn app_handle(&self, s: &SessionRow) -> Secret {
            let secret = handle_value(&*self.rng);
            let h = self.handle_row(s, "app.example.test", &secret);
            self.store
                .sessions()
                .mint_handle(h, None, vec![])
                .await
                .unwrap();
            secret
        }

        async fn code(&self, s: &SessionRow, bind: &Secret, depth: u32) -> Code {
            let secret = random_token(&*self.rng, 32);
            let now = self.clock.now();
            self.store
                .sessions()
                .mint_handoff_code(
                    HandoffCodeRow {
                        code_sha256: secret.digest(),
                        session_id: s.session_id.clone(),
                        host: Host::parse("app.example.test").unwrap(),
                        return_target: Url::parse(URL).unwrap(),
                        client_ip: ip("203.0.113.9"),
                        bind_sha256: bind.digest(),
                        issued_aal: Aal::One,
                        cred_gen: s.cred_gen,
                        recovery_depth: depth,
                        created_at: now,
                        expires_at: now.add(Duration::from_secs(60)),
                        consumed_at: None,
                        consumed_reason: None,
                    },
                    vec![],
                )
                .await
                .unwrap();
            Code {
                secret,
                bind: bind.clone(),
                session: s.clone(),
            }
        }

        fn input(&self, url: &str, code: Option<&Secret>, bind: Option<&Secret>) -> VerifyInput {
            let u = Url::parse(url).unwrap();
            VerifyInput {
                canonical_path: CanonicalPath::new(u.path().to_string()),
                port: 443,
                proto: Scheme::Https,
                host: Host::parse(u.host_str().unwrap()).unwrap(),
                original_url: u,
                client_ip: ip("203.0.113.9"),
                method: http::Method::GET,
                route_id: None,
                cookie_handle: None,
                bind_cookie: bind.cloned(),
                user_agent: None,
                navigation: Navigation::Document,
                handoff: code.map_or(Handoff::None, |c| Handoff::Code(c.clone())),
                contract: 1,
                caller: CallerAuth::Keyed {
                    which: KeySlot::Current,
                },
                request_id: "req".into(),
            }
        }

        async fn run(&self, input: VerifyInput) -> Decision {
            crate::verify::decide(&self.ctx, input).await
        }

        fn count(&self, sql: &str) -> i64 {
            self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }

        async fn events(&self, kind: EventKind) -> Vec<crate::event::types::Event> {
            self.store
                .events()
                .query(EventQuery {
                    kind: Some(kind),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    }

    use crate::crypto::handle_value;
    use crate::event::types::Reason;
    use crate::store::types::EventQuery;

    fn is_login(d: &Decision) -> bool {
        matches!(
            d,
            Decision::Login {
                transaction: Some(_),
                ..
            }
        )
    }

    fn deny_reason(d: &Decision) -> Reason {
        match d {
            Decision::Deny { reason, .. } => *reason,
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn clean_target_preserves_the_rest_of_the_query() {
        let c = |u: &str| clean_target(&Url::parse(u).unwrap()).to_string();
        let want = "https://app.example.test/admin/x?q=1&z=2";
        assert_eq!(
            c("https://app.example.test/admin/x?q=1&_hopae_handoff=K1&z=2"),
            want
        );
        assert_eq!(
            c("https://app.example.test/admin/x?q=1&%5Fhopae%5Fhandoff=K1&z=2"),
            want
        );
        assert_eq!(
            c("https://app.example.test/admin/x?q=1&_hopae_handoff=K1%2B&z=2"),
            want
        );
        assert_eq!(
            c("https://app.example.test/admin/x?_hopae_handoff=K1"),
            "https://app.example.test/admin/x"
        );
        assert_eq!(
            c("https://app.example.test/admin/x?a=1&b"),
            "https://app.example.test/admin/x?a=1&b"
        );
        // A near-miss name is not the parameter.
        assert_eq!(
            c("https://app.example.test/?_hopae_handoff2=K"),
            "https://app.example.test/?_hopae_handoff2=K"
        );
    }

    #[tokio::test]
    #[ignore = "needs W0 request R1 (store completes the new handle's session from the code row)"]
    async fn valid_code_mints_a_handle_and_redirects_to_the_clean_url() {
        let t = t();
        let u = t.user(1).await;
        let (s, _portal) = t.session(&u).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&s, &bind, 0).await;
        let d = t
            .run(t.input(
                &format!("{URL}&_hopae_handoff=K"),
                Some(&code.secret),
                Some(&code.bind),
            ))
            .await;
        let Decision::Handoff {
            location,
            handle,
            issued_aal,
            max_age,
        } = d
        else {
            panic!("expected handoff")
        };
        assert_eq!(location.as_str(), URL);
        assert_eq!(issued_aal, Aal::One);
        assert_eq!(max_age, Duration::from_secs(7 * 86400));
        assert_eq!(
            t.count(&format!(
                "SELECT COUNT(*) FROM session_handles WHERE handle_sha256 = x'{}' AND host = 'app.example.test'",
                handle.digest().to_hex()
            )),
            1
        );
        let ev = t.events(EventKind::SessionHandoff).await;
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].session_id.as_ref(), Some(&code.session.session_id));
        // The handle works, and replaying the code with it is the clean redirect.
        let mut again = t.input(URL, Some(&code.secret), Some(&code.bind));
        again.cookie_handle = Some(handle.clone());
        assert!(matches!(t.run(again).await, Decision::CleanRedirect { .. }));
        let mut next = t.input(URL, None, None);
        next.cookie_handle = Some(handle);
        assert!(matches!(t.run(next).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn non_document_requests_never_consume_the_code() {
        let t = t();
        let u = t.user(1).await;
        let (s, _) = t.session(&u).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&s, &bind, 0).await;
        let mut i = t.input(URL, Some(&code.secret), Some(&code.bind));
        i.navigation = Navigation::Other;
        assert_eq!(
            deny_reason(&t.run(i).await),
            reasons::HANDOFF_PARAMETER_NOT_ALLOWED
        );
        assert_eq!(
            t.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_at IS NOT NULL"),
            0
        );
        let mut amb = t.input(URL, None, Some(&code.bind));
        amb.handoff = Handoff::Ambiguous;
        amb.navigation = Navigation::Other;
        assert_eq!(
            deny_reason(&t.run(amb).await),
            reasons::HANDOFF_PARAMETER_NOT_ALLOWED
        );
        let mut amb = t.input(URL, None, Some(&code.bind));
        amb.handoff = Handoff::Ambiguous;
        assert_eq!(deny_reason(&t.run(amb).await), reasons::HANDOFF_AMBIGUOUS);
        assert_eq!(
            t.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_at IS NOT NULL"),
            0
        );
        assert_eq!(t.count("SELECT COUNT(*) FROM login_txns"), 0);
    }

    #[tokio::test]
    async fn insecure_transport_does_not_burn_the_code() {
        let t = t();
        let u = t.user(1).await;
        let (s, _) = t.session(&u).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&s, &bind, 0).await;
        let mut i = t.input(URL, Some(&code.secret), Some(&code.bind));
        i.proto = Scheme::Http;
        assert_eq!(deny_reason(&t.run(i).await), reasons::INSECURE_TRANSPORT);
        assert_eq!(
            t.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_at IS NOT NULL"),
            0
        );
    }

    #[tokio::test]
    async fn moved_replayed_and_expired_codes_are_burned_and_answer_the_portal() {
        let t = t();
        let u = t.user(1).await;
        let (s, _) = t.session(&u).await;
        let bind = random_token(&*t.rng, 16);
        // Another path on the same host.
        let code = t.code(&s, &bind, 0).await;
        let d = t
            .run(t.input(
                "https://app.example.test/other",
                Some(&code.secret),
                Some(&code.bind),
            ))
            .await;
        assert!(is_login(&d));
        let ev = t.events(EventKind::HandoffRejected).await;
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].client_ip, Some(ip("203.0.113.9")));
        // Replay of the burned code.
        let d = t
            .run(t.input(URL, Some(&code.secret), Some(&code.bind)))
            .await;
        assert!(is_login(&d));
        // Expired.
        let code = t.code(&s, &bind, 0).await;
        t.clock.advance(Duration::from_secs(61));
        let d = t
            .run(t.input(URL, Some(&code.secret), Some(&code.bind)))
            .await;
        assert!(is_login(&d));
        // Unknown code.
        let junk = random_token(&*t.rng, 32);
        assert!(is_login(
            &t.run(t.input(URL, Some(&junk), Some(&bind))).await
        ));
        assert_eq!(t.events(EventKind::HandoffRejected).await.len(), 4);
        // No handle was ever minted for the application host.
        assert_eq!(
            t.count("SELECT COUNT(*) FROM session_handles WHERE host = 'app.example.test'"),
            0
        );
    }

    #[tokio::test]
    #[ignore = "needs W0 request R1 (the store fills the classified reason into the failure events)"]
    async fn failure_events_carry_the_classified_reason() {
        let t = t();
        let (a, b) = (t.user(1).await, t.user(2).await);
        let (sa, _) = t.session(&a).await;
        let (sb, _) = t.session(&b).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&sa, &bind, 0).await;
        t.run(t.input(
            "https://app.example.test/other",
            Some(&code.secret),
            Some(&bind),
        ))
        .await;
        t.run(t.input(URL, Some(&code.secret), Some(&bind))).await;
        let code = t.code(&sa, &bind, 0).await;
        t.clock.advance(Duration::from_secs(61));
        t.run(t.input(URL, Some(&code.secret), Some(&bind))).await;
        let hb = t.app_handle(&sb).await;
        let code = t.code(&sa, &bind, 0).await;
        let mut i = t.input(URL, Some(&code.secret), Some(&bind));
        i.cookie_handle = Some(hb);
        t.run(i).await;
        let mut got: Vec<&str> = t
            .events(EventKind::HandoffRejected)
            .await
            .iter()
            .map(|e| e.reason.map_or("<none>", |r| r.0))
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "code_consumed",
                "code_expired",
                "code_path_mismatch",
                "session_conflict"
            ]
        );
    }

    #[tokio::test]
    async fn binding_race_recovers_at_depth_plus_one_and_stops_at_the_bound() {
        let t = t();
        let u = t.user(1).await;
        let (s, _) = t.session(&u).await;
        let minted_for = random_token(&*t.rng, 16);
        let presented = random_token(&*t.rng, 16);
        for depth in 0..3u32 {
            let code = t.code(&s, &minted_for, depth).await;
            let d = t
                .run(t.input(URL, Some(&code.secret), Some(&presented)))
                .await;
            let Decision::Login {
                transaction: Some(txn),
                bind,
                ..
            } = d
            else {
                panic!("expected a recovery login at depth {depth}")
            };
            assert!(
                matches!(bind, BindAction::Keep),
                "the presented bind is kept"
            );
            let got: i64 = t.count(&format!(
                "SELECT recovery_depth FROM login_txns WHERE txn_sha256 = x'{}'",
                txn.digest().to_hex()
            ));
            assert_eq!(got, i64::from(depth) + 1);
            let bind_ok: i64 = t.count(&format!(
                "SELECT COUNT(*) FROM login_txns WHERE txn_sha256 = x'{}' AND bind_sha256 = x'{}'",
                txn.digest().to_hex(),
                presented.digest().to_hex()
            ));
            assert_eq!(bind_ok, 1);
        }
        // The burned code's depth equals max_recoveries: no transaction, a relayed 403 page.
        let txns = t.count("SELECT COUNT(*) FROM login_txns");
        let code = t.code(&s, &minted_for, 3).await;
        let d = t
            .run(t.input(URL, Some(&code.secret), Some(&presented)))
            .await;
        match d {
            Decision::Deny { reason, kind } => {
                assert_eq!(reason, reasons::HANDOFF_RECOVERY_EXHAUSTED);
                assert_eq!(kind, DenyKind::ForbiddenHtml);
            }
            _ => panic!("expected the exhausted page"),
        }
        assert_eq!(t.count("SELECT COUNT(*) FROM login_txns"), txns);
    }

    #[tokio::test]
    async fn without_any_bind_cookie_a_fresh_one_is_planted() {
        let t = t();
        let u = t.user(1).await;
        let (s, _) = t.session(&u).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&s, &bind, 0).await;
        let d = t.run(t.input(URL, Some(&code.secret), None)).await;
        let Decision::Login { bind, .. } = d else {
            panic!("login")
        };
        assert!(matches!(bind, BindAction::Plant(_)));
    }

    #[tokio::test]
    async fn another_users_handle_leads_to_the_switch_page() {
        let t = t();
        let (a, b) = (t.user(1).await, t.user(2).await);
        let (sa, _) = t.session(&a).await;
        let (sb, _) = t.session(&b).await;
        let hb = t.app_handle(&sb).await;
        let bind = random_token(&*t.rng, 16);
        let code = t.code(&sa, &bind, 0).await;
        let mut i = t.input(URL, Some(&code.secret), Some(&bind));
        i.cookie_handle = Some(hb.clone());
        let Decision::Switch { transaction } = t.run(i).await else {
            panic!("expected switch")
        };
        let row = t
            .store
            .sessions()
            .transaction(&transaction.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.purpose, TxnPurpose::Switch);
        assert_eq!(row.conflicting_handle_sha256, Some(hb.digest()));
        assert_eq!(row.return_target.as_str(), URL);
        assert_eq!(row.portal_session_id.as_ref(), Some(&sa.session_id));
        assert_eq!(row.bind_sha256, Some(bind.digest()));
        // The other user's handle is untouched.
        assert_eq!(
            t.count("SELECT COUNT(*) FROM session_handles WHERE revoked_at IS NOT NULL"),
            0
        );
    }

    #[tokio::test]
    async fn guessing_is_rate_limited_per_ip() {
        let t = t();
        let bind = random_token(&*t.rng, 16);
        for _ in 0..10 {
            let junk = random_token(&*t.rng, 32);
            assert!(is_login(
                &t.run(t.input(URL, Some(&junk), Some(&bind))).await
            ));
        }
        let junk = random_token(&*t.rng, 32);
        match t.run(t.input(URL, Some(&junk), Some(&bind))).await {
            Decision::Deny { reason, kind } => {
                assert_eq!(reason, reasons::RATE_LIMITED);
                assert_eq!(
                    kind,
                    DenyKind::RateLimited {
                        retry_after: Duration::from_secs(60)
                    }
                );
            }
            _ => panic!("expected rate limit"),
        }
        // A minute later the window has slid.
        t.clock.advance(Duration::from_secs(61));
        let junk = random_token(&*t.rng, 32);
        assert!(is_login(
            &t.run(t.input(URL, Some(&junk), Some(&bind))).await
        ));
    }

    #[tokio::test]
    async fn transaction_flood_is_rate_limited_per_ip() {
        let t = t();
        for _ in 0..30 {
            assert!(is_login(&t.run(t.input(URL, None, None)).await));
        }
        match t.run(t.input(URL, None, None)).await {
            Decision::Deny { reason, .. } => assert_eq!(reason, reasons::TXN_RATE_LIMITED),
            _ => panic!("expected the rate limit"),
        }
        // Non-document requests create nothing and are not counted.
        let mut other = t.input(URL, None, None);
        other.navigation = Navigation::Other;
        assert!(matches!(
            t.run(other).await,
            Decision::Login {
                transaction: None,
                ..
            }
        ));
    }
}
