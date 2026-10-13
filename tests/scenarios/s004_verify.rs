//! Scenario 004: verify returns identity headers for a valid session and
//! fails closed otherwise.
//!
//! The engine cases drive `hopae::verify::decide` directly against a real
//! SQLite store (ADR-0013: the decision needs no HTTP). The header and status
//! renderings of the same decisions are asserted by the gateway adapter's own
//! tests (W1-B) and by the wire cases below, which are ignored until that
//! adapter lands.
#![allow(dead_code)]

use crate::support::*;

/// Shared in-process fixture for the engine scenarios (004, 005, 010, 011).
pub(crate) mod fx {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use hopae::crypto::{
        Clock, OsRng, Rng, Secret, TestClock, Timestamp, handle_value, random_id, random_token,
    };
    use hopae::event::types::{Event, EventKind, Reason};
    use hopae::identity::types::NormalizedEmail;
    use hopae::policy::types::{ConfigSnapshot, Host};
    use hopae::provider::types::ProviderId;
    use hopae::session::types::{Aal, FactorEntry, FactorKind, SessionId};
    use hopae::store::types::*;
    use hopae::store::{Store, StoreHooks};
    use hopae::verify::{
        BindAction, Cacheability, CallerAuth, CanonicalPath, Decision, DenyKind, EntryReturn,
        FetchSite, Handoff, Identity, KeySlot, Navigation, Scheme, VerifyContext, VerifyInput,
        decide,
    };

    /// Whole seconds so that the store's second-resolution columns round-trip.
    pub const T0: i64 = 1_800_000_000_000;
    pub const APP_URL: &str = "https://app.example.test/admin/x";
    pub const PORTAL_HOST: &str = "auth.example.test";

    pub fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub fn host(s: &str) -> Host {
        Host::parse(s).unwrap()
    }

    pub fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    pub struct Fx {
        pub _dir: tempfile::TempDir,
        pub store: Store,
        pub hooks: Arc<StoreHooks>,
        pub clock: Arc<TestClock>,
        pub rng: Arc<OsRng>,
        pub snapshot: Arc<ArcSwap<ConfigSnapshot>>,
        pub ctx: VerifyContext,
        pub cfg: hopae::config::Config,
    }

    pub struct Sess {
        pub row: SessionRow,
        pub portal: Secret,
    }

    impl Fx {
        pub fn new(fixture: &str) -> Fx {
            Fx::with(fixture, |_| {})
        }

        /// The named fixture with `patch` applied to its JSON first.
        pub fn with(fixture: &str, patch: impl FnOnce(&mut serde_json::Value)) -> Fx {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(format!("{fixture}.json"));
            let mut v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            patch(&mut v);
            let cfg = hopae::config::parse(&v.to_string()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let clock = Arc::new(TestClock::new(Timestamp(T0)));
            let hooks = Arc::new(StoreHooks::new());
            let store = Store::open(
                &dir.path().join("hopae.db"),
                clock.clone(),
                vec!["log".to_string()],
                Some(hooks.clone()),
            )
            .unwrap();
            store.set_rng(Arc::new(OsRng));
            let rng = Arc::new(OsRng);
            let snapshot = Arc::new(ArcSwap::from_pointee(cfg.snapshot(5)));
            let ctx = VerifyContext::new(
                store.directory(),
                store.sessions(),
                clock.clone(),
                rng.clone(),
                snapshot.clone(),
                cfg.verify_limits(),
            );
            Fx {
                _dir: dir,
                store,
                hooks,
                clock,
                rng,
                snapshot,
                ctx,
                cfg,
            }
        }

        pub fn now(&self) -> Timestamp {
            self.clock.now()
        }

        /// Set the clock to `T0 + secs`.
        pub fn at(&self, secs: u64) {
            self.clock.set(Timestamp(T0).add(Duration::from_secs(secs)));
        }

        pub async fn user(
            &self,
            email: &str,
            username: Option<&str>,
            display: Option<&str>,
        ) -> User {
            let email = NormalizedEmail::parse(email).unwrap();
            self.store
                .directory()
                .create_user(
                    NewUser {
                        primary_email: Some(email.clone()),
                        email_verified: true,
                        email_authoritative: false,
                        display_name: display.map(str::to_string),
                        username: username.map(str::to_string),
                    },
                    NewIdentity {
                        provider_id: ProviderId::new("mock"),
                        subject: format!("sub-{}", random_id(&*self.rng, "x_")),
                        email: Some(email),
                        email_verified: true,
                        email_authoritative: false,
                        name: display.map(str::to_string),
                        picture: None,
                        raw_claims: serde_json::json!({}),
                    },
                    vec![],
                )
                .await
                .unwrap()
        }

        /// A session of `user` bound to 203.0.113.9 with no recorded user
        /// agent, `aal=1`, `cred_gen=2`, created now, plus its portal handle.
        pub async fn session(&self, user: &User) -> Sess {
            self.session_with(user, |_| {}).await
        }

        pub async fn session_with(&self, user: &User, f: impl FnOnce(&mut SessionRow)) -> Sess {
            let now = self.now();
            let mut row = SessionRow {
                session_id: SessionId::new(random_id(&*self.rng, "s_")),
                user_id: user.user_id.clone(),
                provider_id: ProviderId::new("mock"),
                auth_time: now,
                factors: vec![FactorEntry {
                    kind: FactorKind::Oidc,
                    provider: Some(ProviderId::new("mock")),
                    at: now,
                }],
                aal: Aal::One,
                authz_version: user.authz_version,
                cred_gen: 2,
                snapshot: IdentitySnapshot {
                    email: user.primary_email.clone(),
                    display_name: user.display_name.clone(),
                    username: user.username.clone(),
                    groups: vec![],
                },
                bound_ip: ip("203.0.113.9"),
                bound_ua_sha256: None,
                created_at: now,
                last_seen_at: now,
                absolute_expires_at: now.add(self.cfg.session_policy().absolute),
                terminated_at: None,
                terminated_reason: None,
                authz_version_at_auth: user.authz_version,
                auth_time_source: hopae::store::AuthTimeSource::HopaeCompletion,
                bound_ua_prefix: None,
            };
            let before = row.authz_version;
            f(&mut row);
            if row.authz_version != before && row.authz_version_at_auth == before {
                row.authz_version_at_auth = row.authz_version;
            }
            let portal = handle_value(&*self.rng);
            let handle = self.handle_row(&row.session_id, PORTAL_HOST, &portal, |_| {});
            let digest = handle.handle_sha256;
            self.store
                .sessions()
                .create_session(CreateSession {
                    provider_configuration: None,
                    session: row.clone(),
                    portal_handle: handle,
                    portal_handle_digest: digest,
                    consume_txn: None,
                    events: vec![],
                })
                .await
                .unwrap();
            Sess { row, portal }
        }

        fn handle_row(
            &self,
            session: &SessionId,
            host_name: &str,
            secret: &Secret,
            f: impl FnOnce(&mut HandleRow),
        ) -> HandleRow {
            let now = self.now();
            let snap = self.snapshot.load();
            let absolute = Host::parse(host_name)
                .ok()
                .and_then(|h| snap.app_for_host(&h).map(|a| a.session.absolute))
                .unwrap_or(snap.default_app.session.absolute);
            let mut h = HandleRow {
                handle_sha256: secret.digest(),
                session_id: session.clone(),
                host: host(host_name),
                issued_aal: Aal::One,
                created_at: now,
                last_seen_at: now,
                absolute_expires_at: now.add(absolute),
                revoked_at: None,
                revoked_reason: None,
            };
            f(&mut h);
            h
        }

        /// A handle for `host_name`, created now with that application's absolute lifetime.
        pub async fn handle(&self, s: &Sess, host_name: &str) -> Secret {
            self.handle_with(s, host_name, |_| {}).await
        }

        pub async fn handle_with(
            &self,
            s: &Sess,
            host_name: &str,
            f: impl FnOnce(&mut HandleRow),
        ) -> Secret {
            let secret = handle_value(&*self.rng);
            let row = self.handle_row(&s.row.session_id, host_name, &secret, f);
            self.store
                .sessions()
                .mint_handle(row, None, vec![])
                .await
                .unwrap();
            secret
        }

        pub fn req(&self, url: &str) -> Req {
            Req {
                url: url.to_string(),
                ip: ip("203.0.113.9"),
                host: None,
                proto: None,
                cookie: None,
                bind: None,
                ua: None,
                document: true,
                code: None,
                ambiguous: false,
                site: FetchSite::Unknown,
                entry_return: EntryReturn::Absent,
                contract: 1,
            }
        }

        pub async fn decide(&self, r: Req) -> Decision {
            decide(&self.ctx, r.build()).await
        }

        pub fn sql<T: rusqlite::types::FromSql>(&self, sql: &str) -> T {
            self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }

        pub fn exec(&self, sql: &str) {
            self.store.conn().execute_batch(sql).unwrap();
        }

        /// `(revoked_reason, last_seen_at)` of a handle row.
        pub fn handle_state(&self, h: &Secret) -> (Option<String>, i64) {
            self.store
                .conn()
                .query_row(
                    "SELECT revoked_reason, last_seen_at FROM session_handles WHERE handle_sha256 = ?1",
                    [h.digest().0.to_vec()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        }

        /// `(terminated_reason, cred_gen, authz_version)` of a session row.
        pub fn session_state(&self, s: &Sess) -> (Option<String>, i64, i64) {
            self.store
                .conn()
                .query_row(
                    "SELECT terminated_reason, cred_gen, authz_version FROM sessions WHERE session_id = ?1",
                    [s.row.session_id.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap()
        }

        pub async fn events(&self, kind: EventKind) -> Vec<Event> {
            self.store
                .events()
                .query(EventQuery {
                    kind: Some(kind),
                    ..Default::default()
                })
                .await
                .unwrap()
        }

        pub fn store_calls(&self, method: &str) -> u64 {
            self.hooks.calls().get(method).copied().unwrap_or(0)
        }

        pub fn txn_rows(&self) -> i64 {
            self.sql("SELECT COUNT(*) FROM login_txns")
        }
    }

    /// A verify call as the adapter would hand it to the engine.
    #[derive(Clone)]
    pub struct Req {
        url: String,
        ip: IpAddr,
        host: Option<String>,
        proto: Option<Scheme>,
        cookie: Option<Secret>,
        bind: Option<Secret>,
        ua: Option<String>,
        document: bool,
        code: Option<Secret>,
        ambiguous: bool,
        contract: u8,
        site: FetchSite,
        entry_return: EntryReturn,
    }

    impl Req {
        pub fn ip(mut self, v: &str) -> Self {
            self.ip = ip(v);
            self
        }

        pub fn host(mut self, v: &str) -> Self {
            self.host = Some(v.to_string());
            self
        }

        pub fn proto(mut self, v: Scheme) -> Self {
            self.proto = Some(v);
            self
        }

        pub fn cookie(mut self, v: &Secret) -> Self {
            self.cookie = Some(v.clone());
            self
        }

        pub fn raw_cookie(mut self, v: &str) -> Self {
            self.cookie = Some(Secret::new(v.to_string()));
            self
        }

        pub fn bind(mut self, v: &Secret) -> Self {
            self.bind = Some(v.clone());
            self
        }

        pub fn ua(mut self, v: &str) -> Self {
            self.ua = Some(v.to_string());
            self
        }

        pub fn other(mut self) -> Self {
            self.document = false;
            self
        }

        pub fn code(mut self, v: &Secret) -> Self {
            self.code = Some(v.clone());
            self
        }

        pub fn ambiguous(mut self) -> Self {
            self.ambiguous = true;
            self
        }

        pub fn site(mut self, v: FetchSite) -> Self {
            self.site = v;
            self
        }

        /// The adapter's resolution of an entry point's `return` parameter.
        pub fn entry_return(mut self, v: EntryReturn) -> Self {
            self.entry_return = v;
            self
        }

        pub fn contract(mut self, v: u8) -> Self {
            self.contract = v;
            self
        }

        pub fn build(self) -> VerifyInput {
            let url = url::Url::parse(&self.url).unwrap();
            let host_name = self
                .host
                .clone()
                .unwrap_or_else(|| url.host_str().unwrap_or("").to_string());
            VerifyInput {
                canonical_path: CanonicalPath::new(url.path().to_string()),
                port: url.port_or_known_default().unwrap_or(443),
                proto: self.proto.unwrap_or(if url.scheme() == "http" {
                    Scheme::Http
                } else {
                    Scheme::Https
                }),
                original_url: url,
                client_ip: self.ip,
                host: Host::parse(&host_name).unwrap(),
                method: http::Method::GET,
                route_id: None,
                cookie_handle: self.cookie,
                bind_cookie: self.bind,
                user_agent: self.ua,
                navigation: if self.document {
                    Navigation::Document
                } else {
                    Navigation::Other
                },
                accepts_html: self.document,
                fetch_site: self.site,
                entry_return: self.entry_return,
                handoff: match (self.code, self.ambiguous) {
                    (_, true) => Handoff::Ambiguous,
                    (Some(c), false) => Handoff::Code(c),
                    (None, false) => Handoff::None,
                },
                contract: self.contract,
                caller: CallerAuth::Keyed {
                    which: KeySlot::Current,
                },
                request_id: "req-test".to_string(),
            }
        }
    }

    pub fn show(d: &Decision) -> String {
        match d {
            Decision::Allow { .. } => "allow".into(),
            Decision::Login {
                transaction,
                clear_handle,
                ..
            } => format!("login(txn={}, clear={clear_handle})", transaction.is_some()),
            Decision::Handoff { .. } => "handoff".into(),
            Decision::CleanRedirect { .. } => "clean_redirect".into(),
            Decision::Switch { .. } => "switch".into(),
            Decision::AlreadyAuthenticated { .. } => "already_authenticated".into(),
            Decision::LogoutEntry { clear_handle, .. } => {
                format!("logout_entry(clear={clear_handle})")
            }
            Decision::LoggedOut { .. } => "logged_out".into(),
            Decision::Deny { reason, kind } => format!("deny({}, {kind:?})", reason.0),
        }
    }

    pub fn allow(d: Decision) -> (Identity, Cacheability) {
        match d {
            Decision::Allow { identity, cache } => (identity, cache),
            other => panic!("expected allow, got {}", show(&other)),
        }
    }

    /// `(transaction, bind, clear_handle)` of a login decision.
    pub fn login(d: Decision) -> (Option<Secret>, BindAction, bool) {
        match d {
            Decision::Login {
                transaction,
                bind,
                clear_handle,
                ..
            } => (transaction, bind, clear_handle),
            other => panic!("expected login, got {}", show(&other)),
        }
    }

    pub fn deny(d: Decision) -> (Reason, DenyKind) {
        match d {
            Decision::Deny { reason, kind } => (reason, kind),
            other => panic!("expected deny, got {}", show(&other)),
        }
    }

    pub fn random_secret(rng: &dyn Rng, bytes: usize) -> Secret {
        random_token(rng, bytes)
    }
}

use fx::*;
use hopae::event::types::{EventKind, reasons};
use hopae::verify::{BindAction, Cacheability, Decision, DenyKind, Scheme};

/// The user and session of the S004 preconditions: `u` with
/// `authz_version = 3`, session `s` with `aal=1`, `cred_gen=2`, and a handle
/// `H1` on `app.example.test` created at `t0`; configuration generation 5.
async fn precondition(f: &Fx) -> (hopae::store::types::User, Sess, hopae::crypto::Secret) {
    let u = f
        .user("a@example.test", Some("alice"), Some("Alice 김"))
        .await;
    f.exec(&format!(
        "UPDATE users SET authz_version = 3 WHERE user_id = '{}'",
        u.user_id
    ));
    let s = f.session_with(&u, |r| r.authz_version = 3).await;
    let h1 = f.handle(&s, "app.example.test").await;
    f.at(60);
    (u, s, h1)
}

#[tokio::test]
async fn s004_1_valid_handle_yields_identity_headers() {
    let f = Fx::new("m1-basic");
    let (u, s, h1) = precondition(&f).await;
    let before = f.hooks.calls();
    let d = f.decide(f.req(APP_URL).cookie(&h1).ua("UA1")).await;
    let (id, cache) = allow(d);
    assert_eq!(id.user_id, u.user_id);
    assert_eq!(
        id.email.as_ref().map(|e| e.as_str()),
        Some("a@example.test")
    );
    assert_eq!(id.preferred_username.as_deref(), Some("alice"));
    assert!(id.groups.is_empty());
    assert_eq!(id.session_id, s.row.session_id);
    assert_eq!(id.provider_id.as_str(), "mock");
    assert_eq!(id.auth_time.secs(), T0 / 1000);
    // The handle's idle deadline is the earliest timer: t0 + 12 h.
    assert_eq!(id.expires_at.secs(), T0 / 1000 + 12 * 3600);
    assert_eq!(id.aal, hopae::session::types::Aal::One);
    assert_eq!(id.factors.len(), 1);
    assert_eq!(id.factors[0].kind.as_str(), "oidc");
    assert_eq!(id.generations.to_string(), "s2.u3.c5");
    assert!(matches!(cache, Cacheability::NoStore));
    // One handle/session/user read; nothing else is needed to decide.
    let after = f.hooks.calls();
    let delta = |m: &str| after.get(m).copied().unwrap_or(0) - before.get(m).copied().unwrap_or(0);
    assert_eq!(delta("lookup_handle"), 1);
    assert_eq!(delta("user_authz"), 0);
    assert_eq!(delta("user"), 0);
}

#[tokio::test]
async fn s004_2_non_ascii_percent_encoded() {
    // The engine hands the display name over untouched; the adapter
    // percent-encodes it (`Alice%20%EA%B9%80`, tested with the renderer).
    let f = Fx::new("m1-basic");
    let u = f.user("a@example.test", None, Some("Alice 김")).await;
    let s = f.session(&u).await;
    let h1 = f.handle(&s, "app.example.test").await;
    let (id, _) = allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert_eq!(id.preferred_username.as_deref(), Some("Alice 김"));
}

#[test]
fn s004_3_other_cookies_ignored() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .cookie("a", "b")
            .cookie("__Host-hopae", "v1.not-a-handle")
            .cookie("c", "d"),
    );
    // A malformed Hopae cookie is an unknown handle; the foreign cookies are not read.
    assert_eq!(r.status, 302);
    let log = h.log();
    assert!(!log.contains("a=b") && !log.contains("c=d"));
    for ev in h.hooks.events(None, None) {
        assert!(!ev.to_string().contains("a=b"));
    }
}

#[tokio::test]
async fn s004_4_core_decision_without_http() {
    let f = Fx::new("m1-basic");
    let (u, _s, h1) = precondition(&f).await;
    let (id, _) = allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert_eq!(id.user_id, u.user_id);
    // Unknown (well-formed) handle: Login with a transaction.
    let unknown = hopae::crypto::handle_value(&*f.rng);
    let (txn, bind, clear) = login(f.decide(f.req(APP_URL).cookie(&unknown)).await);
    assert!(txn.is_some() && clear);
    assert!(matches!(bind, BindAction::Plant(_)));
}

#[tokio::test]
async fn s004_5_store_unavailable_fails_closed() {
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    f.exec("DROP TABLE session_handles");
    let (reason, kind) = deny(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert_eq!(reason, reasons::STORE_UNAVAILABLE);
    assert_eq!(
        kind,
        DenyKind::Unavailable {
            retry_after: secs(1)
        }
    );
}

#[tokio::test]
async fn s004_6_contract_violation_fails_closed() {
    // The missing `x-original-url` half is the adapter's (W1-B parse tests);
    // the engine refuses a contract major it does not speak.
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    let before = f.hooks.calls();
    let (reason, kind) = deny(f.decide(f.req(APP_URL).cookie(&h1).contract(2)).await);
    assert_eq!(reason, reasons::CONTRACT_UNSUPPORTED);
    assert_eq!(kind, DenyKind::ContractViolation);
    assert_eq!(f.hooks.calls(), before, "no store access");
}

#[tokio::test]
async fn s004_7_host_mismatch_rejected() {
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    let before = f.hooks.calls();
    let (reason, kind) = deny(
        f.decide(f.req(APP_URL).cookie(&h1).host("other.example.org"))
            .await,
    );
    assert_eq!(reason, reasons::CONTRACT_VIOLATION);
    assert_eq!(kind, DenyKind::ContractViolation);
    assert_eq!(f.hooks.calls(), before, "no session lookup");
}

#[tokio::test]
async fn s004_8_cacheability_declared_safely() {
    // verify_cache_seconds = 5 and no step_up rule.
    let five = |v: &mut serde_json::Value| v["apps"][0]["verify_cache_seconds"] = 5.into();
    let f = Fx::with("m1-basic", five);
    let (_u, _s, h1) = precondition(&f).await;
    let (id, cache) = allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
    let now = f.now();
    match cache {
        Cacheability::Private {
            max_age,
            fresh_until,
        } => {
            assert_eq!(max_age, secs(5));
            assert_eq!(fresh_until, now.add(secs(5)));
        }
        Cacheability::NoStore => panic!("expected a cacheable decision"),
    }
    assert_eq!(id.generations.to_string(), "s2.u3.c5");

    // With the handle 2 s from its idle deadline the deadline is read time + 2 s.
    let f = Fx::with("m1-basic", five);
    let (_u, s, _h) = precondition(&f).await;
    let late = f
        .handle_with(&s, "app.example.test", |h| {
            h.last_seen_at = h.created_at.sub(secs(12 * 3600 - 2))
        })
        .await;
    let (_, cache) = allow(f.decide(f.req(APP_URL).cookie(&late)).await);
    match cache {
        Cacheability::Private {
            max_age,
            fresh_until,
        } => {
            assert_eq!(max_age, secs(5));
            assert_eq!(fresh_until, f.now().add(secs(2)));
        }
        Cacheability::NoStore => panic!("expected a cacheable decision"),
    }

    // A step-up rule makes the decision path-dependent: no-store.
    let with_rule = |v: &mut serde_json::Value| {
        v["apps"][0]["verify_cache_seconds"] = 5.into();
        v["apps"][0]["step_up"] =
            serde_json::json!([{"path_prefix": "/admin", "require": {"aal": 2}}]);
    };
    let f = Fx::with("m1-basic", with_rule);
    let (_u, _s, h1) = precondition(&f).await;
    assert!(matches!(
        f.decide(f.req(APP_URL).cookie(&h1)).await,
        Decision::Deny {
            reason: hopae::event::types::reasons::STEP_UP_REQUIRED,
            ..
        }
    ));
    let (_, cache) = allow(
        f.decide(f.req("https://app.example.test/public").cookie(&h1))
            .await,
    );
    assert!(matches!(cache, Cacheability::NoStore));

    // Sixty seconds is refused by the configuration.
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m1-basic.json"),
    )
    .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["apps"][0]["verify_cache_seconds"] = 60.into();
    let Err(err) = hopae::config::parse(&v.to_string()) else {
        panic!("verify_cache_seconds = 60 must be rejected")
    };
    assert!(err.to_string().contains("verify_cache_seconds"), "{err}");
}

#[tokio::test]
async fn s004_9_stalled_dependency_within_budget() {
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    f.hooks.set_stall(5_000);
    let started = std::time::Instant::now();
    let (reason, kind) = deny(f.decide(f.req(APP_URL).cookie(&h1)).await);
    let took = started.elapsed();
    assert_eq!(reason, reasons::BUDGET_EXCEEDED);
    assert!(matches!(kind, DenyKind::Unavailable { .. }));
    assert!(
        took < secs_f(0.45),
        "answered in {took:?}, the budget is 400 ms"
    );
    f.hooks.set_stall(0);
}

fn secs_f(s: f64) -> std::time::Duration {
    std::time::Duration::from_secs_f64(s)
}

#[tokio::test]
async fn s004_10_authz_change_seen_on_next_verify() {
    // refresh (default): groups are dropped, the snapshot is brought up to date.
    let f = Fx::new("m1-basic");
    let (u, s, h1) = precondition(&f).await;
    let admin = hopae::store::types::IdentitySnapshot {
        email: u.primary_email.clone(),
        display_name: u.display_name.clone(),
        username: u.username.clone(),
        groups: vec!["admin".to_string()],
    };
    f.store
        .sessions()
        .refresh_snapshot(&s.row.session_id, admin, 3)
        .await
        .unwrap();
    let (id, _) = allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert_eq!(id.groups, ["admin"]);
    f.exec(&format!(
        "UPDATE users SET authz_version = 4, groups = '[]' WHERE user_id = '{}'",
        u.user_id
    ));
    let (id, _) = allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert!(id.groups.is_empty());
    assert_eq!(id.generations.to_string(), "s2.u4.c5");
    assert_eq!(f.session_state(&s).2, 4, "snapshot refreshed");

    // terminate: the session ends with reason authz_change.
    let f = Fx::with("m1-basic", |v| {
        v["apps"][0]["on_authz_change"] = "terminate".into()
    });
    let (u, s, h1) = precondition(&f).await;
    f.exec(&format!(
        "UPDATE users SET authz_version = 4 WHERE user_id = '{}'",
        u.user_id
    ));
    let (_, _, clear) = login(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert!(clear);
    assert_eq!(f.session_state(&s).0.as_deref(), Some("authz_change"));
    let ev = f.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::AUTHZ_CHANGE));

    // disabled: denied on the very next verify and the session is terminated.
    let f = Fx::new("m1-basic");
    let (u, s, h1) = precondition(&f).await;
    f.exec(&format!(
        "UPDATE users SET status = 'disabled', authz_version = 4 WHERE user_id = '{}'",
        u.user_id
    ));
    let (_, _, clear) = login(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert!(clear);
    assert_eq!(f.session_state(&s).0.as_deref(), Some("user_disabled"));
    let (_, _, clear) = login(f.decide(f.req(APP_URL).other().cookie(&h1)).await);
    assert!(clear);
}

#[tokio::test]
async fn s004_11_no_non_allow_path_is_2xx() {
    use hopae::verify::{EntryReturn, FetchSite};
    // Every engine outcome except Decision::Allow maps to a non-2xx status in
    // the adapter (its unit test walks `render`); here every non-allow fixture
    // must at least not be an Allow, and the one allow carries an identity.
    let f = Fx::with("m1-two-domains", |_| {});
    let (u, s, h1) = precondition(&f).await;
    let unknown = hopae::crypto::handle_value(&*f.rng);
    let mut outcomes: Vec<(&str, Decision)> = vec![];
    outcomes.push(("no cookie document", f.decide(f.req(APP_URL)).await));
    outcomes.push(("no cookie other", f.decide(f.req(APP_URL).other()).await));
    outcomes.push((
        "unknown handle",
        f.decide(f.req(APP_URL).cookie(&unknown)).await,
    ));
    outcomes.push((
        "unknown host",
        f.decide(f.req("https://nope.example.test/").cookie(&h1))
            .await,
    ));
    outcomes.push((
        "contract",
        f.decide(f.req(APP_URL).cookie(&h1).contract(9)).await,
    ));
    outcomes.push((
        "http",
        f.decide(f.req(APP_URL).cookie(&h1).proto(Scheme::Http))
            .await,
    ));
    outcomes.push((
        "param on non-document",
        f.decide(f.req(APP_URL).other().cookie(&h1).ambiguous())
            .await,
    ));
    outcomes.push(("ambiguous", f.decide(f.req(APP_URL).ambiguous()).await));
    outcomes.push((
        "unknown code",
        f.decide(f.req(APP_URL).code(&unknown)).await,
    ));
    // ADR-0015: the reserved namespace and the application-host entry points
    // never produce an Allow either.
    let root = "https://app.example.test";
    let reserved = f
        .decide(f.req(&format!("{root}/_hopae/verify")).cookie(&h1))
        .await;
    assert!(
        matches!(&reserved, Decision::Deny { reason, .. } if *reason == hopae::event::types::reasons::RESERVED_PATH),
        "{}",
        show(&reserved)
    );
    outcomes.push(("reserved path", reserved));
    outcomes.push((
        "reserved path, mixed case",
        f.decide(f.req(&format!("{root}/_HOPAE/x")).cookie(&h1))
            .await,
    ));
    let not_document = f
        .decide(f.req(&format!("{root}/_hopae/logout")).other().cookie(&h1))
        .await;
    assert!(
        matches!(&not_document, Decision::Deny { reason, .. } if *reason == hopae::event::types::reasons::ENTRY_POINT_NOT_DOCUMENT),
        "{}",
        show(&not_document)
    );
    outcomes.push(("entry point, non-document", not_document));
    let refused = f
        .decide(
            f.req(&format!("{root}/_hopae/login"))
                .cookie(&h1)
                .entry_return(EntryReturn::Invalid),
        )
        .await;
    assert!(
        matches!(&refused, Decision::Deny { reason, .. } if *reason == hopae::event::types::reasons::RETURN_NOT_ALLOWED),
        "{}",
        show(&refused)
    );
    outcomes.push(("entry point, return not allowed", refused));
    let entry = f
        .decide(
            f.req(&format!("{root}/_hopae/logout"))
                .cookie(&h1)
                .site(FetchSite::SameOrigin),
        )
        .await;
    assert!(
        matches!(
            &entry,
            Decision::LogoutEntry {
                clear_handle: false,
                ..
            }
        ),
        "{}",
        show(&entry)
    );
    outcomes.push(("logout entry", entry));
    let already = f
        .decide(f.req(&format!("{root}/_hopae/login")).cookie(&h1))
        .await;
    assert!(
        matches!(&already, Decision::AlreadyAuthenticated { location } if location.as_str() == "https://app.example.test/"),
        "{}",
        show(&already)
    );
    outcomes.push(("login entry, live session", already));
    outcomes.push((
        "login entry, no session",
        f.decide(f.req(&format!("{root}/_hopae/login"))).await,
    ));
    // The no-confirmation mode, on its own configuration: the session ends and
    // the answer is the redirect to the portal's signed-out page, never an Allow.
    let direct = Fx::new("m1-logout-direct");
    let (_u2, s2, g1) = precondition(&direct).await;
    let ended = direct
        .decide(
            direct
                .req(&format!("{root}/_hopae/logout"))
                .cookie(&g1)
                .site(FetchSite::SameOrigin),
        )
        .await;
    assert!(
        matches!(&ended, Decision::LoggedOut { .. }),
        "{}",
        show(&ended)
    );
    assert_eq!(direct.session_state(&s2).0.as_deref(), Some("logout"));
    outcomes.push(("direct logout", ended));
    outcomes.push((
        "binding mismatch",
        f.decide(f.req(APP_URL).cookie(&h1).ip("198.51.100.7"))
            .await,
    ));
    // ADR-0016: a console session that fails the freshness predicate is sent to
    // a reauthentication (the handle kept), never allowed: `302` for a document
    // navigation, `401` otherwise.
    {
        use hopae::verify::LoginKind;
        let a = Fx::new("m4-admin");
        let au = a.user("c@example.test", None, None).await;
        let stale = a.session(&au).await; // auth_time_source = hopae_completion
        let ah = a.handle(&stale, "hopae-admin.example.test").await;
        a.at(60);
        let console = "https://hopae-admin.example.test/users";
        let doc = a.decide(a.req(console).cookie(&ah)).await;
        assert!(
            matches!(
                &doc,
                Decision::Login {
                    kind: LoginKind::Reauth,
                    transaction: Some(_),
                    clear_handle: false,
                    ..
                }
            ),
            "{}",
            show(&doc)
        );
        outcomes.push(("reauth, document", doc));
        let other = a.decide(a.req(console).other().cookie(&ah)).await;
        assert!(
            matches!(
                &other,
                Decision::Login {
                    kind: LoginKind::Reauth,
                    transaction: None,
                    clear_handle: false,
                    ..
                }
            ),
            "{}",
            show(&other)
        );
        outcomes.push(("reauth, other", other));
        // The same session on the application host is not asked for it, and a
        // provider-verified session is let into the console.
        let ok = a.handle(&stale, "app.example.test").await;
        assert!(matches!(
            a.decide(a.req(APP_URL).cookie(&ok)).await,
            Decision::Allow { .. }
        ));
        let au2 = a.user("d@example.test", None, None).await;
        let claimed = a
            .session_with(&au2, |r| {
                r.auth_time_source = hopae::store::types::AuthTimeSource::ProviderClaim
            })
            .await;
        let ch = a.handle(&claimed, "hopae-admin.example.test").await;
        assert!(matches!(
            a.decide(a.req(console).cookie(&ch)).await,
            Decision::Allow { .. }
        ));
    }
    for (what, d) in &outcomes {
        assert!(!matches!(d, Decision::Allow { .. }), "{what}: {}", show(d));
    }
    // The session was terminated by the binding mismatch: even the right IP is denied now.
    assert!(!matches!(
        f.decide(f.req(APP_URL).cookie(&h1)).await,
        Decision::Allow { .. }
    ));
    let _ = (u, s);
    // The adapter half (R-7): the walk over every decision shape, every reason
    // code and every deny kind, for both navigation kinds, asserting that only
    // `Allow` ever renders to a 2xx. Exposed by the `test-hooks` feature; the
    // same walk runs as a unit test in `src/gateway/hangang/tests.rs`.
    #[cfg(feature = "test-hooks")]
    hopae::gateway::hangang::assert_only_allow_is_2xx();
}

#[tokio::test]
async fn s004_a1_malformed_handle_rejected_early() {
    let f = Fx::new("m1-basic");
    let (_u, _s, _h1) = precondition(&f).await;
    let before = f.store_calls("lookup_handle");
    let short = format!("v1.{}", "a".repeat(10));
    let bad_version = format!("v9.{}", "a".repeat(43));
    for bad in [short, bad_version] {
        let (txn, _, clear) = login(f.decide(f.req(APP_URL).raw_cookie(&bad)).await);
        assert!(txn.is_some() && clear);
    }
    assert_eq!(f.store_calls("lookup_handle"), before, "no store query");
    // The 9 KiB cookie header is refused by the adapter (`400 header_too_large`, W1-B).
}

#[tokio::test(flavor = "multi_thread")]
async fn s004_a2_last_seen_coalesced() {
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    let mut latencies = Vec::new();
    for i in 0..1000u64 {
        // 10 s of requests in 10 ms steps, starting 60 s after t0.
        f.clock
            .set(hopae::crypto::Timestamp(T0 + 60_000 + (i as i64) * 10));
        let started = std::time::Instant::now();
        let d = f.decide(f.req(APP_URL).cookie(&h1)).await;
        latencies.push(started.elapsed());
        allow(d);
    }
    latencies.sort();
    assert!(
        latencies[989] < std::time::Duration::from_millis(20),
        "p99 {:?}",
        latencies[989]
    );
    // Let the detached touch finish, then count the writes.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(f.store_calls("touch_handle") <= 1);
    assert!(f.store_calls("touch_handle") >= 1);
}

#[test]
fn s004_a3_concurrency_limit_fails_closed() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            serde_json::json!({"limits": {"gateway_max_concurrent": 64},"gateway":{"verify_budget_ms":2000}}),
        ),
        &idp,
        &[],
    );
    // Start the burst only once all clients exist; hold admitted work long enough
    // to measure saturation rather than thread-creation or scheduler stagger.
    h.hooks.stall(1000);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(201));
    let h = std::sync::Arc::new(h);
    let mut threads = vec![];
    for _ in 0..200 {
        let h = h.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            h.verify(VerifyRequest::document("https://app.example.test/admin/x"))
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let overloaded = results
        .iter()
        .filter(|r| r.status == 503 && r.header("x-hopae-reason") == Some("overloaded"))
        .count();
    assert!(overloaded >= 200 - 64, "{overloaded} overloaded answers");
    assert!(
        results
            .iter()
            .filter(|r| r.header("x-hopae-reason") == Some("overloaded"))
            .all(|r| r.header("retry-after").is_some())
    );
    h.hooks.stall_off();
    // The per-address transaction cap is enforced in the one store write that
    // inserts the row (ADR-0015), so the 64 admitted concurrent calls from one
    // address cannot overshoot `txn.per_ip_per_minute` (30) any more; that
    // address is now rate limited and a fresh one is served.
    let r = h.verify(VerifyRequest::document("https://app.example.test/admin/x").ip("192.0.2.77"));
    assert_eq!(r.status, 302);
    let stored: i64 = rusqlite::Connection::open(h.state_dir.path().join("state").join("hopae.db"))
        .unwrap()
        .query_row("SELECT count(*) FROM login_txns", [], |r| r.get(0))
        .unwrap();
    assert!(stored <= 31, "the cap holds under concurrency: {stored}");
}

#[tokio::test]
async fn s004_a4_handle_not_valid_on_other_host() {
    let f = Fx::new("m1-two-domains");
    let (_u, s, h1) = precondition(&f).await;
    let (txn, _, clear) = login(
        f.decide(f.req("https://other.example.org/").cookie(&h1))
            .await,
    );
    assert!(txn.is_some() && clear);
    assert_eq!(f.session_state(&s).0, None, "the session is not terminated");
    // And H1 still works on its own host.
    allow(f.decide(f.req(APP_URL).cookie(&h1)).await);
}

#[test]
fn s004_a5_duplicate_context_headers_rejected() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(Fixture::new("m1-basic"), &idp, &[]);
    let r = h.verify(
        VerifyRequest::document("https://app.example.test/admin/x")
            .header("x-forwarded-host", "other.example.org"),
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.header("x-hopae-reason"), Some("contract_violation"));
    assert_eq!(h.hooks.store_calls("lookup_handle"), 0);
}

#[tokio::test]
async fn s004_a6_downgraded_proto_refused() {
    let f = Fx::new("m1-basic");
    let (_u, _s, h1) = precondition(&f).await;
    let before = f.hooks.calls();
    let (reason, kind) = deny(
        f.decide(f.req(APP_URL).cookie(&h1).proto(Scheme::Http))
            .await,
    );
    assert_eq!(reason, reasons::INSECURE_TRANSPORT);
    assert_eq!(kind, DenyKind::ContractViolation);
    assert_eq!(f.hooks.calls(), before);
}

#[tokio::test]
async fn s004_a7_unknown_and_expired_uniform() {
    let f = Fx::new("m1-basic");
    let (_u, s, h1) = precondition(&f).await;
    let random = hopae::crypto::handle_value(&*f.rng);
    f.store
        .sessions()
        .terminate_session(&s.row.session_id, reasons::LOGOUT, f.now(), vec![])
        .await
        .unwrap();
    let shape = |d: Decision| {
        let (txn, bind, clear) = login(d);
        (txn.is_some(), matches!(bind, BindAction::Plant(_)), clear)
    };
    let unknown = shape(f.decide(f.req(APP_URL).cookie(&random)).await);
    let terminated = shape(f.decide(f.req(APP_URL).cookie(&h1)).await);
    assert_eq!(unknown, terminated);
    assert_eq!(unknown, (true, true, true));
}

#[test]
fn s004_a8_caller_key_required() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::new("m1-basic"),
        &idp,
        &[("HOPAE_GW_KEY_B", "second-key-value")],
    );
    let url = "https://app.example.test/admin/x";
    for req in [
        VerifyRequest::document(url).key(KeySlot::Missing),
        VerifyRequest::document(url).key(KeySlot::Wrong),
        VerifyRequest::document(url).header(
            "x-hopae-gateway-key",
            &h.key_value(&KeySlot::Current).unwrap(),
        ),
    ] {
        let r = h.verify(req);
        assert_eq!(r.status, 403);
        assert_eq!(r.header("x-hopae-reason"), Some("caller_unauthorized"));
        assert!(r.set_cookies().is_empty());
    }
    assert_eq!(h.hooks.store_calls("lookup_handle"), 0);
    assert_eq!(h.hooks.store_calls("create_transaction"), 0);
    assert_eq!(
        h.hooks.counters()["metrics"]["hopae_verify_unauthorized_total"],
        3
    );
    // The comparison itself is constant time (W0's `ct_eq`).
    assert!(hopae::crypto::ct_eq(b"abcdefgh", b"abcdefgh"));
    assert!(!hopae::crypto::ct_eq(b"abcdefgh", b"abcdefgx"));
    assert!(!hopae::crypto::ct_eq(b"abcdefgh", b"abcdefg"));
}

/// G7-C02: one session spanning a `refresh` app and a `terminate` app. The
/// refresh app's snapshot update must not hide the authorization change from
/// the terminate app, whichever is visited first.
#[tokio::test]
async fn g7_c02_refresh_app_does_not_defeat_terminate_app() {
    for refresh_first in [true, false] {
        let f = Fx::with("m1-basic", |v| {
            v["apps"].as_array_mut().unwrap().insert(
                1,
                serde_json::json!({
                    "app_id": "strict",
                    "display_name": "strict",
                    "hosts": ["strict.example.test"],
                    "ports": [443],
                    "on_authz_change": "terminate",
                    "verify_cache_seconds": 0
                }),
            );
        });
        let u = f.user("a@example.test", Some("alice"), None).await;
        f.exec(&format!(
            "UPDATE users SET authz_version = 3 WHERE user_id = '{}'",
            u.user_id
        ));
        let s = f.session_with(&u, |r| r.authz_version = 3).await;
        let ha = f.handle(&s, "app.example.test").await;
        let hb = f.handle(&s, "strict.example.test").await;
        f.at(60);
        f.exec(&format!(
            "UPDATE users SET authz_version = 4 WHERE user_id = '{}'",
            u.user_id
        ));
        let a_url = APP_URL;
        let b_url = "https://strict.example.test/x";
        if refresh_first {
            allow(f.decide(f.req(a_url).cookie(&ha)).await);
            let (_, _, clear) = login(f.decide(f.req(b_url).cookie(&hb)).await);
            assert!(
                clear,
                "refresh_first: the terminate app must force re-authentication"
            );
            assert_eq!(f.session_state(&s).0.as_deref(), Some("authz_change"));
        } else {
            let (_, _, clear) = login(f.decide(f.req(b_url).cookie(&hb)).await);
            assert!(clear);
            assert_eq!(f.session_state(&s).0.as_deref(), Some("authz_change"));
            let (_, _, clear) = login(f.decide(f.req(a_url).cookie(&ha)).await);
            assert!(clear, "a terminated session serves no app");
        }
    }
}

// ---- gateway layer (W2-A) ---------------------------------------------------
//
// S004-11 and S004-A8 through the real gateway: what the client and the
// upstream see. The names do not start with `s004_` because the mapped cases
// above are the scenario's tests; these add the gateway-wire half.

mod gateway_layer {
    use std::time::Duration;

    use crate::support::gateway::*;
    use crate::support::*;

    const KEY: &str = "x-hopae-gateway-key";

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn gateway_s004_11_no_non_allow_path_is_2xx() {
        let Some(s) = Stack::with_routes(
            "s004_11",
            GatewayRoutes::standard().host_neutral("/neutral"),
        ) else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, APP_HOST, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        s.echo.clear();

        let mut outcomes: Vec<(String, u16)> = Vec::new();
        let mut check = |name: &str, r: Response, allowed: &[u16]| {
            assert!(
                allowed.contains(&r.status),
                "{name}: status {} not in {allowed:?}",
                r.status
            );
            assert!(
                !(200..300).contains(&r.status),
                "{name}: a 2xx for a non-allow outcome"
            );
            assert!(
                r.header("x-hangang-auth-terminal").is_none(),
                "{name}: terminal marker"
            );
            outcomes.push((name.to_string(), r.status));
        };

        // no cookie: document and non-document
        let anon = s.gw.browser();
        check(
            "no cookie, document",
            anon.get(APP_HOST, "/admin/x"),
            &[302],
        );
        check(
            "no cookie, non-document",
            anon.fetch(APP_HOST, "/admin/x"),
            &[401, 403, 302],
        );
        // unknown handle (a well-formed but never issued value)
        let unknown = s.gw.browser();
        let r = unknown.get_with(
            APP_HOST,
            "/admin/x",
            &[("cookie", &format!("__Host-hopae=v1.{}", "A".repeat(43)))],
        );
        check("unknown handle", r, &[302]);
        // binding mismatch: the right handle from another address
        check(
            "binding mismatch",
            b.at_ip("198.51.100.77").get(APP_HOST, "/admin/x"),
            &[302, 403],
        );
        // unknown host on a host-neutral route
        check(
            "unknown host",
            anon.get("evil.example.org", "/neutral/x"),
            &[403],
        );
        // the reserved parameter: non-document, ambiguous
        check(
            "reserved parameter, non-document",
            anon.fetch(APP_HOST, "/admin/x?_hopae_handoff=abc"),
            &[403],
        );
        check(
            "ambiguous parameter",
            anon.get_cross_site(APP_HOST, "/admin/x?_hopae_handoff=a&_hopae_handoff=b"),
            &[403],
        );
        // caller key missing / contract violation (the call as a broken gateway would send it)
        s.gw.tap.set_mods(TapMods {
            drop_request_headers: vec![KEY.into()],
            ..TapMods::default()
        });
        check("caller key missing", anon.get(APP_HOST, "/admin/x"), &[403]);
        s.gw.tap.set_mods(TapMods {
            drop_request_headers: vec!["x-forwarded-proto".into()],
            ..TapMods::default()
        });
        check(
            "contract violation",
            anon.get(APP_HOST, "/admin/x"),
            &[403, 503],
        );
        s.gw.tap.reset_mods();
        // overload of the store: every call stalls past the verify budget
        s.hopae.hooks.stall(2_000);
        check("stalled store", anon.get(APP_HOST, "/admin/x"), &[503]);
        s.hopae.hooks.stall_off();
        // rate limit of handoff failures (10 per minute per address)
        let noisy = s.gw.browser().at_ip("198.51.100.99");
        let mut last = None;
        for i in 0..12 {
            let r = noisy.get_cross_site(
                APP_HOST,
                &format!("/admin/x?_hopae_handoff=made-up-code-{i}"),
            );
            assert!(!(200..300).contains(&r.status), "attempt {i}: {r:?}");
            last = Some(r);
        }
        check("rate limit", last.unwrap(), &[403]);
        // an expired handle
        s.hopae.advance(Duration::from_secs(8 * 24 * 3600));
        check("expired handle", b.get(APP_HOST, "/admin/x"), &[302]);

        eprintln!("S004-11 gateway outcomes: {outcomes:?}");
        assert!(
            s.echo.requests().is_empty(),
            "no non-allow outcome reached the upstream: {outcomes:?}"
        );
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn gateway_s004_11_the_only_200_is_the_allow() {
        let Some(s) = Stack::basic("s004_11_allow") else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, APP_HOST, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        s.echo.clear();
        let r = b.get(&s.app, "/admin/x");
        assert_eq!(r.status, 200);
        let seen = s.echo.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].header("x-forwarded-user").is_some(),
            "identity headers"
        );
        let a = s.gw.tap.answers().pop().unwrap();
        assert_eq!(a.status, 200);
        assert!(a.header("x-hangang-auth-terminal").is_none());
    }

    #[test]
    #[ignore = "gateway layer: needs HOPAE_E2E_GATEWAY_BINARY (make e2e)"]
    fn gateway_s004_a8_caller_key_required() {
        let Some(s) = Stack::basic("s004_a8") else {
            return;
        };
        let b = s.gw.browser();
        let l = b.login(&s.idp, APP_HOST, "/admin/x");
        assert_eq!(l.handoff.status, 302);
        s.echo.clear();
        s.gw.tap.clear();
        let key = s.hopae.env_value(KEY_ENV).unwrap().to_string();
        let lookups = s.hopae.hooks.store_calls("lookup_handle");
        let creates = s.hopae.hooks.store_calls("create_transaction");
        let txns = txn_count(&s.hopae);
        let unauthorized = |s: &Stack| {
            s.hopae.hooks.counters()["metrics"]["hopae_verify_unauthorized_total"]
                .as_u64()
                .unwrap_or(0)
        };
        assert_eq!(unauthorized(&s), 0);

        let variants: [(&str, TapMods); 3] = [
            (
                "missing",
                TapMods {
                    drop_request_headers: vec![KEY.into()],
                    ..TapMods::default()
                },
            ),
            (
                "wrong",
                TapMods {
                    request_headers: vec![(KEY.into(), "not-the-key".into())],
                    ..TapMods::default()
                },
            ),
            (
                "duplicated",
                TapMods {
                    request_headers: vec![(KEY.into(), key.clone()), (KEY.into(), key.clone())],
                    ..TapMods::default()
                },
            ),
        ];
        for (name, mods) in variants {
            s.gw.tap.set_mods(mods);
            let r = b.get(APP_HOST, "/admin/x");
            assert_eq!(r.status, 403, "{name}: relayed to the client: {r:?}");
            assert!(r.set_cookies().is_empty(), "{name}: no cookie");
            let a = s.gw.tap.answers().pop().unwrap();
            assert_eq!(a.status, 403, "{name}");
            assert_eq!(
                a.header("x-hopae-reason"),
                Some("caller_unauthorized"),
                "{name}"
            );
            assert!(
                a.header_all("set-cookie").is_empty(),
                "{name}: no binding cookie"
            );
        }
        s.gw.tap.reset_mods();
        assert!(s.echo.requests().is_empty(), "the upstream saw nothing");
        assert_eq!(
            s.hopae.hooks.store_calls("lookup_handle"),
            lookups,
            "no store read"
        );
        assert_eq!(s.hopae.hooks.store_calls("create_transaction"), creates);
        assert_eq!(txn_count(&s.hopae), txns, "no transaction");
        assert_eq!(unauthorized(&s), 3, "hopae_verify_unauthorized_total");
        // The right key (the gateway's own static header) is processed as S004-1.
        let ok = b.get(APP_HOST, "/admin/x");
        assert_eq!(ok.status, 200);
    }
}

#[tokio::test]
async fn stepup_requires_actual_second_factor_freshness_and_fixed_handle_level() {
    use fx::*;
    use hopae::event::types::reasons;
    use hopae::session::types::{Aal, FactorEntry, FactorKind};
    use hopae::verify::{Decision, LoginKind};
    for (name, session_aal, handle_aal, kind, age, allowed) in [
        ("initial", Aal::One, Aal::One, None, 0, false),
        ("number_only", Aal::Two, Aal::Two, None, 0, false),
        (
            "oidc_only",
            Aal::Two,
            Aal::Two,
            Some(FactorKind::Oidc),
            0,
            false,
        ),
        (
            "fresh_totp_old_primary",
            Aal::Two,
            Aal::Two,
            Some(FactorKind::Totp),
            0,
            true,
        ),
        (
            "old_totp",
            Aal::Two,
            Aal::Two,
            Some(FactorKind::Totp),
            301,
            false,
        ),
        (
            "future_totp",
            Aal::Two,
            Aal::Two,
            Some(FactorKind::Totp),
            -1,
            false,
        ),
        (
            "old_handle",
            Aal::Two,
            Aal::One,
            Some(FactorKind::Totp),
            0,
            false,
        ),
        (
            "low_session",
            Aal::One,
            Aal::Two,
            Some(FactorKind::Totp),
            0,
            false,
        ),
    ] {
        let f = Fx::with("m1-basic", |v| {
            v["apps"][0]["step_up"] =
                serde_json::json!([{"path_prefix":"/admin","require":{"aal":2,"max_age":300}}]);
        });
        let user = f.user("stepup@example.test", None, None).await;
        let session = f
            .session_with(&user, |s| {
                s.aal = session_aal;
                if name == "fresh_totp_old_primary" {
                    s.auth_time = hopae::crypto::Timestamp(T0 - 3_600_000);
                }
                if let Some(kind) = kind {
                    s.factors.push(FactorEntry {
                        kind,
                        provider: None,
                        at: hopae::crypto::Timestamp(T0 - age * 1000),
                    });
                }
            })
            .await;
        let handle = f
            .handle_with(&session, "app.example.test", |h| h.issued_aal = handle_aal)
            .await;
        for path in ["/admin/x", "/ADMIN/x", "/%61dmin/x"] {
            let url = format!("https://app.example.test{path}");
            let mut document_input = f.req(&url).cookie(&handle).build();
            document_input.canonical_path =
                hopae::gateway::canonical::canonical_path(path).unwrap();
            let document = hopae::verify::decide(&f.ctx, document_input).await;
            if allowed {
                assert!(matches!(document, Decision::Allow { .. }), "{name} {path}");
            } else {
                assert!(
                    matches!(
                        document,
                        Decision::Deny {
                            reason: reasons::STEP_UP_REQUIRED,
                            ..
                        }
                    ),
                    "{name} {path}"
                );
            }
            let mut api_input = f.req(&url).cookie(&handle).other().build();
            api_input.canonical_path = hopae::gateway::canonical::canonical_path(path).unwrap();
            let api = hopae::verify::decide(&f.ctx, api_input).await;
            if allowed {
                assert!(matches!(api, Decision::Allow { .. }), "{name}");
            } else {
                assert!(
                    matches!(
                        api,
                        Decision::Login {
                            kind: LoginKind::StepUp,
                            clear_handle: false,
                            ..
                        }
                    ),
                    "{name}"
                );
            }
        }
        assert!(
            matches!(
                f.decide(f.req("https://app.example.test/public").cookie(&handle))
                    .await,
                Decision::Allow { .. }
            ),
            "{name}"
        );
        assert_eq!(
            f.txn_rows(),
            0,
            "no unsupported browser challenge for {name}"
        );
    }
}

#[tokio::test]
async fn primary_freshness_rule_starts_reauthentication_without_an_otp_loop() {
    use fx::*;
    use hopae::verify::{Decision, LoginKind};
    for otp in [false, true] {
        let mut f = Fx::with("m1-basic", |v| {
            v["apps"][0]["step_up"] =
                serde_json::json!([{"path_prefix":"/admin","require":{"aal":1,"max_age":60}}]);
        });
        f.ctx.limits.stepup_enabled = otp;
        let (_user, _session, handle) = precondition(&f).await;
        f.clock.set(hopae::crypto::Timestamp(T0 + 61_000));
        assert!(matches!(
            f.decide(f.req(APP_URL).cookie(&handle)).await,
            Decision::Login {
                kind: LoginKind::Reauth,
                transaction: Some(_),
                clear_handle: false,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn native_session_receipt_uses_engine_seal_and_refuses_modified_claims() {
    use hopae::auth_gateway::{
        receipt::Purpose,
        receipt_issuer::{Configuration, Issuer, Request, Scope},
        receipt_keys::{Key, Registry},
    };
    use hopae::crypto::Clock;
    let f = Fx::new("m1-basic");
    let (_, _, handle) = precondition(&f).await;
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public_key = key.verifying_key().to_bytes();
    let configuration = Configuration {
        issuer_ref: "hopae-owned".into(),
        key_epoch: 1,
        identity_authority_epoch: "identity-epoch-1".into(),
        public_key,
        scopes: vec![Scope {
            service: "app".into(),
            audience: "app-api".into(),
        }],
    };
    let issuer = Issuer::new(
        configuration.clone(),
        zeroize::Zeroizing::new([7; 32]),
        f.clock.clone(),
        f.rng.clone(),
    )
    .unwrap();
    let registry = Registry::compile(
        1,
        &[Key {
            issuer_ref: "hopae-owned".into(),
            purpose: Purpose::Authentication,
            epoch: 1,
            public_key,
        }],
        None,
    )
    .unwrap();
    let mut wrong_pin = configuration;
    wrong_pin.public_key = [3; 32];
    assert!(
        Issuer::new(
            wrong_pin,
            zeroize::Zeroizing::new([7; 32]),
            f.clock.clone(),
            f.rng.clone()
        )
        .is_err()
    );
    let request = || Request {
        service: "app",
        audience: "app-api",
        request_sha256: [4; 32],
    };
    let (identity, _) = allow(f.decide(f.req(APP_URL).cookie(&handle).ua("UA1")).await);
    let issued = issuer
        .issue_session(&identity, request(), &|| Ok(()))
        .unwrap();
    let verified = registry
        .verify(
            &issued.context(),
            None,
            issued.bytes(),
            f.clock.now().0 as u64,
        )
        .unwrap();
    assert_eq!(
        verified.claims().expires_ms - verified.claims().issued_ms,
        1000
    );
    assert_eq!(
        issued.context().identity.subject_ref,
        identity.user_id.as_str()
    );
    assert_eq!(issued.context().identity.aal, 1);
    assert_eq!(issued.context().identity.revision, 3);
    assert_eq!(issued.context().identity.credential_generation, 2);
    assert_eq!(
        issued.context().identity_authority_epoch,
        "identity-epoch-1:5"
    );
    let second = issuer
        .issue_session(&identity, request(), &|| Ok(()))
        .unwrap();
    assert_ne!(issued.bytes(), second.bytes());
    assert!(
        issuer
            .issue_session(
                &identity,
                Request {
                    service: "another-service",
                    ..request()
                },
                &|| panic!("wrong service reached live guard")
            )
            .is_err()
    );
    assert!(
        issuer
            .issue_session(
                &identity,
                Request {
                    audience: "undeclared-api",
                    ..request()
                },
                &|| panic!("undeclared audience reached guard")
            )
            .is_err()
    );
    for field in 0..9 {
        let (mut changed, _) = allow(f.decide(f.req(APP_URL).cookie(&handle).ua("UA1")).await);
        match field {
            0 => changed.user_id = hopae::identity::types::UserId::new("another-user"),
            1 => changed.session_id = hopae::session::types::SessionId::new("another-session"),
            2 => changed.provider_id = hopae::provider::types::ProviderId::new("another-provider"),
            3 => changed.auth_time.0 += 1,
            4 => changed.expires_at.0 += 1,
            5 => changed.aal = hopae::session::types::Aal::Two,
            6 => changed.generations.user += 1,
            7 => changed.generations.session += 1,
            _ => changed.generations.config += 1,
        }
        assert!(
            issuer
                .issue_session(&changed, request(), &|| panic!(
                    "changed identity reached live guard"
                ))
                .is_err()
        );
    }
    let checks = std::cell::Cell::new(0);
    assert!(
        issuer
            .issue_session(&identity, request(), &|| {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(hopae::auth_gateway::receipt_keys::Refused)
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(checks.get(), 2);
    let base = f.clock.now();
    assert!(
        issuer
            .issue_session(&identity, request(), &|| {
                f.clock.set(hopae::crypto::Timestamp(base.0 + 1000));
                Ok(())
            })
            .is_err()
    );
    f.clock.set(base);
    assert!(
        issuer
            .issue_session(&identity, request(), &|| panic!(
                "expired proof revived after clock rollback"
            ))
            .is_err()
    );
}
