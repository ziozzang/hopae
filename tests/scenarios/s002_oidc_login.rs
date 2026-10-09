//! Scenario 002: login with an OIDC provider creates a session.
//!
//! W1-D tests the session and identity services in process: the real SQLite
//! store, a scripted provider, the injected clock. The HTTP surface (portal
//! pages, cookies, CSRF) belongs to W1-E and is exercised once it lands; where
//! a case's assertions are about state and events, they are made here, where
//! they are about the wire, the test says so.
//!
//! `kit` is shared with `s003_handoff.rs` and `s006_logout.rs`.
#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use hopae::crypto::Secret;
use hopae::event::types::{EventKind, reasons};
use hopae::provider::types::{CallbackQuery, ProviderError, ProviderId};
use hopae::session::{CallbackOutcome, LoginEntry, SessionError};

use kit::*;

pub(crate) mod kit {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use hopae::config::{LinkConflict, LinkMode};
    use hopae::crypto::{
        Clock, Digest, OsRng, Rng, Secret, TestClock, Timestamp, random_token, sha256,
    };
    use hopae::event::types::{Event, EventKind};
    use hopae::identity::linking::LinkingPolicy;
    use hopae::identity::types::NormalizedEmail;
    use hopae::policy::types::{AppId, AppPolicy, ConfigSnapshot, Host, SessionPolicy};
    use hopae::provider::types::{
        AuthorizationRequest, CallbackQuery, Provider, ProviderError, ProviderHealth, ProviderId,
        ProviderIdentity, ProviderKind,
    };
    use hopae::session::{
        CallbackOutcome, CodeDirectory, Deps, ProviderLookup, RedeemInput, RedeemResult,
        RequestCtx, Service, ServiceConfig, StartedLogin,
    };
    use hopae::store::types::*;
    use hopae::store::{Store, StoreResult};
    use url::Url;

    pub const T0: i64 = 1_760_000_000_000;
    pub const PORTAL: &str = "auth.example.test";
    pub const APP: &str = "app.example.test";
    pub const OTHER: &str = "other.example.org";
    pub const IP: &str = "203.0.113.9";
    pub const UA: &str = "Mozilla/5.0 (kit)";

    pub fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub fn host(s: &str) -> Host {
        Host::parse(s).unwrap()
    }

    pub fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    pub type Script = Box<dyn Fn() -> Result<ProviderIdentity, ProviderError> + Send + Sync>;

    pub fn ident(
        sub: &str,
        email: &str,
        verified: bool,
        authoritative: bool,
        name: &str,
    ) -> ProviderIdentity {
        ProviderIdentity {
            subject: sub.into(),
            email: NormalizedEmail::parse(email).ok(),
            email_verified: verified,
            email_authoritative: authoritative,
            name: Some(name.into()),
            username: None,
            picture: None,
            raw_claims: serde_json::json!({"sub": sub}),
        }
    }

    /// A provider whose `complete` answer is scripted and whose calls are counted.
    pub struct FakeProvider {
        id: ProviderId,
        pub script: Mutex<Script>,
        pub begins: AtomicUsize,
        pub completes: AtomicUsize,
        pub delay: Mutex<Duration>,
        pub omit_nonce: AtomicBool,
        states: Mutex<HashMap<Digest, Secret>>,
    }

    impl FakeProvider {
        pub fn new(id: &str) -> Arc<FakeProvider> {
            Arc::new(FakeProvider {
                id: ProviderId::new(id),
                script: Mutex::new(Box::new(|| {
                    Ok(ident("sub-1", "a@example.test", true, false, "Alice 김"))
                })),
                begins: AtomicUsize::new(0),
                completes: AtomicUsize::new(0),
                delay: Mutex::new(Duration::ZERO),
                omit_nonce: AtomicBool::new(false),
                states: Mutex::new(HashMap::new()),
            })
        }

        pub fn set(
            &self,
            f: impl Fn() -> Result<ProviderIdentity, ProviderError> + Send + Sync + 'static,
        ) {
            *self.script.lock().unwrap() = Box::new(f);
        }

        pub fn set_identity(
            &self,
            sub: &'static str,
            email: &'static str,
            verified: bool,
            authoritative: bool,
            name: &'static str,
        ) {
            self.set(move || Ok(ident(sub, email, verified, authoritative, name)));
        }

        pub fn completes(&self) -> usize {
            self.completes.load(Ordering::SeqCst)
        }

        /// The `state` value the provider issued for the transaction.
        pub fn state_for(&self, txn: &Secret) -> Secret {
            self.states
                .lock()
                .unwrap()
                .get(&txn.digest())
                .cloned()
                .expect("state issued")
        }
    }

    #[async_trait]
    impl Provider for FakeProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }
        fn kind(&self) -> ProviderKind {
            ProviderKind::Oidc
        }
        fn display_name(&self) -> &str {
            "Mock"
        }
        fn enabled(&self) -> bool {
            true
        }
        async fn begin(
            &self,
            txn: &TransactionRow,
            redirect_uri: &Url,
            rng: &dyn Rng,
        ) -> Result<AuthorizationRequest, ProviderError> {
            self.begins.fetch_add(1, Ordering::SeqCst);
            let state = random_token(rng, 24);
            let nonce = random_token(rng, 16);
            let verifier = random_token(rng, 32);
            let mut u = url("https://idp.example.test/authorize");
            u.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", redirect_uri.as_str())
                .append_pair("state", state.expose());
            if !self.omit_nonce.load(Ordering::SeqCst) {
                u.query_pairs_mut().append_pair("nonce", nonce.expose());
            }
            // The kit keys states by the transaction digest the service gives
            // the provider, so tests can find the state for a transaction.
            self.states
                .lock()
                .unwrap()
                .insert(txn_key(txn), state.clone());
            let omit = self.omit_nonce.load(Ordering::SeqCst);
            Ok(AuthorizationRequest {
                url: u,
                state,
                nonce: (!omit).then(|| nonce.expose().to_string()),
                pkce_verifier: (!omit).then_some(verifier),
            })
        }
        async fn complete(
            &self,
            txn: &TransactionRow,
            callback: &CallbackQuery,
            _redirect_uri: &Url,
            _now: Timestamp,
        ) -> Result<ProviderIdentity, ProviderError> {
            self.completes.fetch_add(1, Ordering::SeqCst);
            let d = *self.delay.lock().unwrap();
            if !d.is_zero() {
                tokio::time::sleep(d).await;
            }
            // Like the real provider: the state must be the one issued for this transaction.
            let ok = callback
                .state
                .as_deref()
                .is_some_and(|s| Some(sha256(s.as_bytes())) == txn.state_sha256);
            if !ok {
                return Err(ProviderError::InvalidState);
            }
            (self.script.lock().unwrap())()
        }
        async fn health(&self) -> ProviderHealth {
            ProviderHealth::Ok
        }
    }

    fn txn_key(txn: &TransactionRow) -> Digest {
        txn.txn_sha256
    }

    pub struct Providers(pub Vec<Arc<FakeProvider>>);

    impl ProviderLookup for Providers {
        fn get(&self, id: &ProviderId) -> Option<Arc<dyn Provider>> {
            self.0
                .iter()
                .find(|p| p.id() == id)
                .map(|p| p.clone() as Arc<dyn Provider>)
        }
        fn enabled_sorted(&self) -> Vec<Arc<dyn Provider>> {
            self.0
                .iter()
                .map(|p| p.clone() as Arc<dyn Provider>)
                .collect()
        }
    }

    /// `Sessions::handoff_code` stand-in: a non-consuming read of a code row
    /// through the store's utility connection.
    pub struct SqlCodes(pub Store);

    #[async_trait]
    impl CodeDirectory for SqlCodes {
        async fn handoff_code(&self, d: &Digest) -> StoreResult<Option<HandoffCodeRow>> {
            let conn = self.0.conn();
            let mut st = conn
                .prepare("SELECT session_id, host, return_target, client_ip, bind_sha256, issued_aal, cred_gen, recovery_depth, created_at, expires_at, consumed_at, consumed_reason FROM handoff_codes WHERE code_sha256=?1")
                .unwrap();
            let row = st
                .query_row([d.0.to_vec()], |r| {
                    let bind: Vec<u8> = r.get(4)?;
                    Ok(HandoffCodeRow {
                        code_sha256: *d,
                        session_id: hopae::session::SessionId::new(r.get::<_, String>(0)?),
                        host: Host::parse(&r.get::<_, String>(1)?).unwrap(),
                        return_target: Url::parse(&r.get::<_, String>(2)?).unwrap(),
                        client_ip: r.get::<_, String>(3)?.parse().unwrap(),
                        bind_sha256: Digest::from_slice(&bind).unwrap(),
                        issued_aal: hopae::session::Aal::from_i64(r.get(5)?).unwrap(),
                        cred_gen: r.get::<_, i64>(6)? as u64,
                        recovery_depth: r.get::<_, i64>(7)? as u32,
                        created_at: Timestamp::from_secs(r.get(8)?),
                        expires_at: Timestamp::from_secs(r.get(9)?),
                        consumed_at: r.get::<_, Option<i64>>(10)?.map(Timestamp::from_secs),
                        consumed_reason: r.get(11)?,
                    })
                })
                .ok();
            Ok(row)
        }
    }

    #[derive(Clone)]
    pub struct Opts {
        pub sso_confirm: bool,
        pub max_recoveries: u32,
        pub failures_per_minute: u32,
        pub txn_max_rows: u32,
        pub txn_per_ip: u32,
        pub linking: LinkingPolicy,
        pub provider_auto_link: bool,
        pub authoritative_domains: Vec<String>,
        pub allowed_domains: Vec<String>,
    }

    impl Default for Opts {
        fn default() -> Self {
            Opts {
                sso_confirm: false,
                max_recoveries: 3,
                failures_per_minute: 10,
                txn_max_rows: 1000,
                txn_per_ip: 30,
                linking: LinkingPolicy::default(),
                provider_auto_link: false,
                authoritative_domains: vec![],
                allowed_domains: vec![],
            }
        }
    }

    pub struct Kit {
        pub store: Store,
        pub clock: Arc<TestClock>,
        pub svc: Service,
        pub mock: Arc<FakeProvider>,
        pub mock2: Arc<FakeProvider>,
        /// `__Host-hopae_bind` on the application hosts and `__Host-hopae_portal` on the portal.
        pub b1: Secret,
        pub p1: Secret,
        pub opts: Opts,
        _dir: tempfile::TempDir,
    }

    /// A completed login.
    pub struct Logged {
        pub location: Url,
        pub code: Secret,
        pub target: Url,
        pub session_id: hopae::session::SessionId,
        pub user_id: hopae::identity::types::UserId,
        pub portal_handle: Secret,
        pub txn: Secret,
    }

    pub fn app_policy(id: &str, h: &str) -> AppPolicy {
        AppPolicy {
            app_id: AppId::new(id),
            display_name: id.into(),
            hosts: vec![host(h)],
            ports: vec![443],
            ..AppPolicy::default_app()
        }
    }

    pub fn provider_row(
        id: &str,
        auto_link: bool,
        authoritative: &[String],
        allowed: &[String],
    ) -> ProviderRow {
        ProviderRow {
            provider_id: ProviderId::new(id),
            kind: ProviderKind::Oidc,
            display_name: id.into(),
            enabled: true,
            managed_by: ManagedBy::File,
            deleted_at: None,
            sort_order: 0,
            config: serde_json::json!({}),
            client_secret_env: None,
            allowed_email_domains: allowed.to_vec(),
            authoritative_domains: authoritative.to_vec(),
            auto_link,
            trust_email: false,
        }
    }

    impl Kit {
        pub async fn new() -> Kit {
            Kit::with(Opts::default()).await
        }

        pub async fn with(opts: Opts) -> Kit {
            let dir = tempfile::tempdir().unwrap();
            let clock = Arc::new(TestClock::new(Timestamp(T0)));
            let store = Store::open(
                &dir.path().join("hopae.db"),
                clock.clone(),
                vec!["log".into()],
                None,
            )
            .unwrap();
            let rng: Arc<dyn Rng> = Arc::new(OsRng);
            store.set_rng(rng.clone());
            let snapshot = Arc::new(ArcSwap::from_pointee(ConfigSnapshot {
                generation: 1,
                apps: vec![app_policy("app", APP), app_policy("other", OTHER)],
                default_app: AppPolicy::default_app(),
                providers: vec![],
            }));
            let mock = FakeProvider::new("mock");
            let mock2 = FakeProvider::new("mock2");
            store
                .directory()
                .import_providers(
                    vec![
                        provider_row(
                            "mock",
                            opts.provider_auto_link,
                            &opts.authoritative_domains,
                            &opts.allowed_domains,
                        ),
                        provider_row("mock2", false, &[], &[]),
                        provider_row("trusted1", false, &[], &[]),
                    ],
                    None,
                    vec![],
                )
                .await
                .unwrap();
            let svc = Service::new(Deps {
                directory: store.directory(),
                sessions: store.sessions(),
                events: store.events(),
                codes: Arc::new(SqlCodes(store.clone())),
                clock: clock.clone(),
                rng,
                snapshot,
                providers: Arc::new(Providers(vec![mock.clone(), mock2.clone()])),
                config: ServiceConfig {
                    portal_host: host(PORTAL),
                    portal_url: url("https://auth.example.test"),
                    secure: true,
                    session: SessionPolicy::default(),
                    txn_max_rows: opts.txn_max_rows,
                    txn_per_ip_per_minute: opts.txn_per_ip,
                    handoff_failures_per_minute: opts.failures_per_minute,
                    max_recoveries: opts.max_recoveries,
                    sso_confirm_new_host: opts.sso_confirm,
                    linking: opts.linking,
                },
            });
            Kit {
                store,
                clock,
                svc,
                mock,
                mock2,
                b1: random_token(&OsRng, 16),
                p1: random_token(&OsRng, 16),
                opts,
                _dir: dir,
            }
        }

        pub fn ctx(&self) -> RequestCtx {
            self.ctx_ip(IP)
        }

        pub fn ctx_ip(&self, addr: &str) -> RequestCtx {
            RequestCtx {
                client_ip: ip(addr),
                user_agent: Some(UA.into()),
                request_id: "req-kit".into(),
            }
        }

        pub fn advance(&self, secs: u64) {
            self.clock.advance(Duration::from_secs(secs));
        }

        pub fn now(&self) -> Timestamp {
            self.clock.now()
        }

        pub fn mock_id(&self) -> ProviderId {
            ProviderId::new("mock")
        }

        /// Flow 1: a login transaction for `https://<host><path_query>` from `IP`.
        pub async fn start(
            &self,
            host_name: &str,
            path_query: &str,
            bind: Option<&Secret>,
        ) -> StartedLogin {
            self.svc
                .start_login(
                    &self.ctx(),
                    &url(&format!("https://{host_name}{path_query}")),
                    bind,
                    0,
                )
                .await
                .expect("start_login")
        }

        /// Flow 2: the provider redirect for `txn`; returns the issued `state`.
        pub async fn redirect(&self, txn: &Secret, portal: &Secret) -> Secret {
            self.svc
                .begin_provider(&self.ctx(), txn, &self.mock_id(), Some(portal))
                .await
                .expect("begin_provider");
            self.mock.state_for(txn)
        }

        /// Flow 3: the provider callback on `/callback/mock`.
        pub async fn callback(
            &self,
            state: &Secret,
            portal: Option<&Secret>,
            handle: Option<&Secret>,
        ) -> Result<CallbackOutcome, hopae::session::SessionError> {
            self.callback_on(&self.mock_id(), state, portal, handle)
                .await
        }

        pub async fn callback_on(
            &self,
            provider: &ProviderId,
            state: &Secret,
            portal: Option<&Secret>,
            handle: Option<&Secret>,
        ) -> Result<CallbackOutcome, hopae::session::SessionError> {
            self.svc
                .complete_callback(
                    &self.ctx(),
                    provider,
                    CallbackQuery {
                        code: Some("AC1".into()),
                        state: Some(state.expose().to_string()),
                        error: None,
                        error_description: None,
                    },
                    portal,
                    handle,
                )
                .await
        }

        /// The whole of Flows 1-3 for the application host with the kit's cookies.
        pub async fn login_to(&self, host_name: &str, path_query: &str) -> Logged {
            let started = self.start(host_name, path_query, Some(&self.b1)).await;
            let state = self.redirect(&started.transaction, &self.p1).await;
            let out = self
                .callback(&state, Some(&self.p1), None)
                .await
                .expect("callback");
            self.logged(out, started.transaction)
        }

        pub async fn login(&self) -> Logged {
            self.login_to(APP, "/admin/x?a=1").await
        }

        pub fn logged(&self, out: CallbackOutcome, txn: Secret) -> Logged {
            match out {
                CallbackOutcome::LoggedIn {
                    location,
                    session_id,
                    user_id,
                    portal_handle,
                    ..
                } => Logged {
                    code: code_of(&location),
                    target: strip_handoff(&location),
                    location,
                    session_id,
                    user_id,
                    portal_handle: portal_handle
                        .expect("new session has a portal handle")
                        .value,
                    txn,
                },
                other => panic!("expected LoggedIn, got {other:?}"),
            }
        }

        /// Redeem on the application host as the browser with the given cookies.
        pub async fn redeem(
            &self,
            code: &Secret,
            target: &Url,
            bind: Option<&Secret>,
            handle: Option<&Secret>,
        ) -> RedeemResult {
            self.redeem_from(IP, code, target, bind, handle).await
        }

        pub async fn redeem_from(
            &self,
            addr: &str,
            code: &Secret,
            target: &Url,
            bind: Option<&Secret>,
            handle: Option<&Secret>,
        ) -> RedeemResult {
            self.svc
                .redeem(RedeemInput {
                    code: code.clone(),
                    target: target.clone(),
                    client_ip: ip(addr),
                    user_agent: Some(UA.into()),
                    bind_cookie: bind.cloned(),
                    handle_cookie: handle.cloned(),
                    request_id: "req-redeem".into(),
                })
                .await
                .expect("redeem")
        }

        pub fn count(&self, sql: &str) -> i64 {
            self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }

        pub fn text(&self, sql: &str) -> Option<String> {
            self.store.conn().query_row(sql, [], |r| r.get(0)).ok()
        }

        pub async fn events(&self, kind: EventKind) -> Vec<Event> {
            self.store
                .events()
                .query(EventQuery {
                    kind: Some(kind),
                    limit: Some(1000),
                    ..Default::default()
                })
                .await
                .unwrap()
        }

        /// ADR-0008 elevation, as M5 will do it: one transaction raises `aal`,
        /// bumps `cred_gen`, revokes every handle and consumes every outstanding code.
        pub fn elevate(&self, session: &str) {
            let at = self.now().secs();
            let conn = self.store.conn();
            conn.execute_batch(&format!(
                "BEGIN IMMEDIATE;
                 UPDATE sessions SET aal=2, cred_gen=cred_gen+1 WHERE session_id='{session}';
                 UPDATE session_handles SET revoked_at={at}, revoked_reason='elevation' WHERE session_id='{session}' AND revoked_at IS NULL;
                 UPDATE handoff_codes SET consumed_at={at}, consumed_reason='elevation' WHERE session_id='{session}' AND consumed_at IS NULL;
                 COMMIT;"
            ))
            .unwrap();
        }
    }

    pub fn code_of(location: &Url) -> Secret {
        let v = location
            .query_pairs()
            .find(|(k, _)| k == "_hopae_handoff")
            .map(|(_, v)| v.to_string())
            .expect("handoff parameter");
        Secret::new(v)
    }

    /// The location without the reserved parameter (always the last one the service appends).
    pub fn strip_handoff(location: &Url) -> Url {
        let s = location.as_str();
        let i = s.rfind("_hopae_handoff=").expect("handoff parameter");
        let base = s[..i].trim_end_matches(['&', '?']);
        Url::parse(base).unwrap()
    }

    pub fn sha(s: &Secret) -> Digest {
        s.digest()
    }
}

fn reason_of(e: &SessionError) -> &'static str {
    e.reason().0
}

// ---- main flow ------------------------------------------------------------

#[tokio::test]
async fn s002_1_start_stores_state_nonce_pkce() {
    let k = Kit::new().await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;

    let row = k
        .store
        .sessions()
        .transaction(&started.transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.provider_id, Some(ProviderId::new("mock")));
    assert_eq!(
        row.state_sha256,
        Some(state.digest()),
        "state is stored as a digest"
    );
    assert!(row.nonce.as_deref().is_some_and(|n| !n.is_empty()));
    assert!(row.pkce_verifier.is_some());
    assert_eq!(
        row.portal_bind_sha256,
        Some(k.p1.digest()),
        "recorded at the provider redirect"
    );
    assert_eq!(row.bind_sha256, Some(k.b1.digest()));
    // `login.started` was emitted once, with the transaction, and not again by the redirect.
    assert_eq!(k.events(EventKind::LoginStarted).await.len(), 1);
    // The raw state never reaches the store.
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM login_txns WHERE state_sha256 = x'{}'",
            state.digest()
        )),
        1
    );
}

#[tokio::test]
async fn s002_2_callback_validates_and_creates_session() {
    let k = Kit::new().await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let out = k.callback(&state, Some(&k.p1), None).await.unwrap();
    let CallbackOutcome::LoggedIn {
        location,
        session_id,
        portal_handle,
        created_user,
        reused_session,
        ..
    } = out
    else {
        panic!("expected LoggedIn");
    };
    assert!(created_user && !reused_session);
    assert_eq!(location.host_str(), Some(APP));
    assert_eq!(location.path(), "/admin/x");
    let code = code_of(&location);
    let handle = portal_handle.expect("portal handle");
    assert_eq!(
        handle.max_age.as_secs(),
        7 * 86400,
        "portal handle lives for the default application's absolute lifetime"
    );

    assert_eq!(k.mock.completes(), 1);
    // user
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 1);
    assert_eq!(
        k.text("SELECT primary_email FROM users").as_deref(),
        Some("a@example.test")
    );
    assert_eq!(k.count("SELECT authz_version FROM users"), 1);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM identities WHERE provider_id='mock' AND subject='sub-1'"),
        1
    );
    // session
    assert_eq!(
        k.text("SELECT provider_id FROM sessions").as_deref(),
        Some("mock")
    );
    assert_eq!(k.count("SELECT aal FROM sessions"), 1);
    assert_eq!(k.count("SELECT cred_gen FROM sessions"), 1);
    assert_eq!(k.count("SELECT authz_version FROM sessions"), 1);
    assert_eq!(k.text("SELECT bound_ip FROM sessions").as_deref(), Some(IP));
    assert_eq!(k.count("SELECT length(bound_ua_sha256) FROM sessions"), 32);
    let factors: serde_json::Value =
        serde_json::from_str(&k.text("SELECT factors FROM sessions").unwrap()).unwrap();
    assert_eq!(factors[0]["kind"], "oidc");
    assert_eq!(factors[0]["provider"], "mock");
    assert_eq!(
        factors[0]["at"].as_i64(),
        Some(T0),
        "factor time is the injected clock"
    );
    // portal handle row: host = portal, issued_aal = 1, stored as a digest
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM session_handles WHERE session_id='{session_id}' AND host='{PORTAL}' AND issued_aal=1 AND handle_sha256 = x'{}'",
            handle.value.digest()
        )),
        1
    );
    // first handoff code: bound to the application host, path, ip, bind digest
    assert_eq!(k.count("SELECT COUNT(*) FROM handoff_codes"), 1);
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM handoff_codes WHERE code_sha256 = x'{}' AND host='{APP}' AND return_path='/admin/x' AND client_ip='{IP}' AND bind_sha256 = x'{}' AND issued_aal=1 AND cred_gen=1 AND recovery_depth=0 AND expires_at = created_at + 60",
            code.digest(),
            k.b1.digest()
        )),
        1
    );
    // the transaction is consumed; events travel with the session
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
        1
    );
    assert_eq!(k.events(EventKind::LoginSucceeded).await.len(), 1);
    assert_eq!(k.events(EventKind::SessionCreated).await.len(), 1);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM event_deliveries d JOIN events e ON e.event_id=d.event_id WHERE e.kind IN ('login.succeeded','session.created')"),
        2
    );
    // no secret value in any event row
    let dump = k
        .text("SELECT group_concat(attrs || coalesce(reason,'') || request_id, '|') FROM events")
        .unwrap_or_default();
    assert!(
        !dump.contains(state.expose())
            && !dump.contains(code.expose())
            && !dump.contains(handle.value.expose())
    );
}

#[tokio::test]
async fn s002_3_returning_identity_reused() {
    let k = Kit::new().await;
    let first = k.login().await;
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 1);
    k.advance(120);
    k.mock.set_identity(
        "sub-1",
        "a@example.test",
        true,
        false,
        "Alice Kim (new name)",
    );
    // a new transaction from the same browser, no portal handle presented
    let started = k.start(APP, "/admin/y", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let out = k.callback(&state, Some(&k.p1), None).await.unwrap();
    let CallbackOutcome::LoggedIn {
        user_id,
        created_user,
        ..
    } = out
    else {
        panic!()
    };
    assert!(!created_user, "no new user");
    assert_eq!(user_id, first.user_id);
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 1);
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 1);
    assert_eq!(
        k.text("SELECT name FROM identities").as_deref(),
        Some("Alice Kim (new name)")
    );
    assert!(
        k.count("SELECT last_seen_at FROM identities")
            > k.count("SELECT first_seen_at FROM identities")
    );
    assert_eq!(
        k.text("SELECT primary_email FROM users").as_deref(),
        Some("a@example.test")
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions"),
        2,
        "a second session row"
    );
}

async fn existing_user_with_email(k: &Kit, authoritative: bool) {
    // user u_1 came from provider `trusted1` with a@example.test
    let ident = ident("t-1", "a@example.test", true, authoritative, "Existing");
    k.store
        .directory()
        .create_user(
            hopae::store::types::NewUser {
                primary_email: ident.email.clone(),
                email_verified: true,
                email_authoritative: authoritative,
                display_name: Some("Existing".into()),
                username: None,
            },
            hopae::store::types::NewIdentity {
                provider_id: ProviderId::new("trusted1"),
                subject: "t-1".into(),
                email: ident.email.clone(),
                email_verified: true,
                email_authoritative: authoritative,
                name: Some("Existing".into()),
                picture: None,
                raw_claims: serde_json::json!({}),
            },
            vec![],
        )
        .await
        .unwrap();
}

async fn assert_link_required(k: &Kit) {
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let out = k.callback(&state, Some(&k.p1), None).await.unwrap();
    let CallbackOutcome::LinkRequired { transaction } = out else {
        panic!("expected LinkRequired, got {out:?}");
    };
    // nothing created
    assert_eq!(
        k.count("SELECT COUNT(*) FROM users"),
        1,
        "only the existing user"
    );
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 1);
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM handoff_codes"), 0);
    // the pending identity travels in a `link` transaction with a fresh 10-minute expiry
    let row = k
        .store
        .sessions()
        .transaction(&transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.purpose, hopae::store::types::TxnPurpose::Link);
    assert!(row.pending_identity.is_some());
    assert_eq!(
        row.expires_at,
        k.now().add(std::time::Duration::from_secs(600))
    );
    let pending = row.pending_identity.unwrap().to_string();
    assert!(pending.contains("sub-1") && !pending.contains("raw_claims"));
    // the login transaction is consumed, the conflict is an event with the reason
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
        1
    );
    let ev = k.events(EventKind::IdentityConflict).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::LINK_REQUIRED));
    assert!(
        !ev[0].to_json().to_string().contains("a@example.test"),
        "no email in the event"
    );
}

#[tokio::test]
async fn s002_4_email_collision_refuses_with_link_notice() {
    let k = Kit::new().await;
    existing_user_with_email(&k, false).await;
    assert_link_required(&k).await;
    // the same outcome when the assertion is unverified
    let k = Kit::new().await;
    existing_user_with_email(&k, false).await;
    k.mock
        .set_identity("sub-1", "a@example.test", false, false, "Alice");
    assert_link_required(&k).await;
}

#[tokio::test]
async fn s002_5_authoritative_email_auto_links_when_opted_in() {
    let opted = Opts {
        provider_auto_link: true,
        authoritative_domains: vec!["example.test".into()],
        ..Opts::default()
    };
    // opted in, authoritative on both sides: linked automatically
    let k = Kit::with(opted.clone()).await;
    existing_user_with_email(&k, true).await;
    k.mock
        .set_identity("sub-1", "a@example.test", true, true, "Alice");
    let existing = k.text("SELECT user_id FROM users").unwrap();
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let out = k.callback(&state, Some(&k.p1), None).await.unwrap();
    let CallbackOutcome::LoggedIn {
        user_id,
        auto_linked,
        created_user,
        ..
    } = out
    else {
        panic!()
    };
    assert!(auto_linked && !created_user);
    assert_eq!(user_id.as_str(), existing);
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 1);
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM identities WHERE provider_id='mock' AND user_id='{existing}'"
        )),
        1
    );
    let linked = k.events(EventKind::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].reason, Some(reasons::AUTHORITATIVE_EMAIL));

    // every missing condition falls back to the notice of S002-4
    let cases: Vec<(&str, Opts, bool, (bool, bool))> = vec![
        (
            "no hd (not authoritative)",
            opted.clone(),
            true,
            (true, false),
        ),
        (
            "different hd domain",
            Opts {
                authoritative_domains: vec!["other.test".into()],
                ..opted.clone()
            },
            true,
            (true, true),
        ),
        (
            "auto_link off",
            Opts {
                provider_auto_link: false,
                ..opted.clone()
            },
            true,
            (true, true),
        ),
        (
            "existing user not authoritative",
            opted.clone(),
            false,
            (true, true),
        ),
    ];
    for (name, o, existing_authoritative, (verified, authoritative)) in cases {
        let k = Kit::with(o).await;
        existing_user_with_email(&k, existing_authoritative).await;
        k.mock
            .set_identity("sub-1", "a@example.test", verified, authoritative, "Alice");
        eprintln!("case: {name}");
        assert_link_required(&k).await;
    }
}

#[tokio::test]
async fn s002_6_sso_from_portal_handle() {
    let k = Kit::new().await;
    let first = k.login().await;
    let auth_time = k.count("SELECT auth_time FROM sessions");
    let completes = k.mock.completes();
    k.advance(30);
    // a new transaction for the second application, with its own bind cookie
    let b2 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let t2 = k.start(OTHER, "/", Some(&b2)).await;
    let entry = k
        .svc
        .sso_or_chooser(&k.ctx(), &t2.transaction, Some(&first.portal_handle), false)
        .await
        .unwrap();
    let LoginEntry::Sso {
        location,
        session_id,
    } = entry
    else {
        panic!("expected Sso, got {entry:?}")
    };
    assert_eq!(session_id, first.session_id);
    assert_eq!(location.host_str(), Some(OTHER));
    assert_eq!(location.path(), "/");
    let code = code_of(&location);
    assert_eq!(
        k.mock.begins.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the first login called the provider"
    );
    assert_eq!(k.mock.completes(), completes, "no provider call for SSO");
    assert_eq!(
        k.count("SELECT auth_time FROM sessions"),
        auth_time,
        "auth_time unchanged"
    );
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
    // the code is bound to the second host's bind cookie
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM handoff_codes WHERE code_sha256 = x'{}' AND host='{OTHER}' AND bind_sha256 = x'{}'",
            code.digest(),
            b2.digest()
        )),
        1
    );
    let ev = k.events(EventKind::SessionHandoff).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].attrs.get("sso"), Some(&serde_json::Value::Bool(true)));
    assert_eq!(
        ev[0].attrs.get("host").and_then(|h| h.as_str()),
        Some(OTHER)
    );
    // the transaction is consumed: a second visit is refused
    let again = k
        .svc
        .sso_or_chooser(&k.ctx(), &t2.transaction, Some(&first.portal_handle), false)
        .await;
    assert_eq!(reason_of(&again.unwrap_err()), "txn_consumed");
    // without a handle the same visit lists providers
    let t3 = k.start(OTHER, "/", Some(&b2)).await;
    let entry = k
        .svc
        .sso_or_chooser(&k.ctx(), &t3.transaction, None, false)
        .await
        .unwrap();
    let LoginEntry::Chooser { providers } = entry else {
        panic!("expected Chooser")
    };
    assert_eq!(providers.len(), 2);
    // a revoked/unknown handle is no SSO either
    let bogus = hopae::crypto::handle_value(&hopae::crypto::OsRng);
    let entry = k
        .svc
        .sso_or_chooser(&k.ctx(), &t3.transaction, Some(&bogus), false)
        .await
        .unwrap();
    assert!(matches!(entry, LoginEntry::Chooser { .. }));
}

#[tokio::test]
async fn s002_7_portal_binding_race_recovers() {
    let k = Kit::new().await;
    let p2 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    // two tabs; TA's provider redirect was issued with P1 (immutable from then on)
    let ta = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let tb = k.start(APP, "/admin/y", Some(&k.b1)).await;
    let sa = k.redirect(&ta.transaction, &k.p1).await;
    // the jar ended with P2: TB's redirect records P2
    let sb = k.redirect(&tb.transaction, &p2).await;

    // a lure visit cannot re-bind TA
    let lure = k
        .svc
        .begin_provider(&k.ctx(), &ta.transaction, &k.mock_id(), Some(&p2))
        .await;
    assert!(matches!(lure, Err(SessionError::AlreadyBound)));
    let row = k
        .store
        .sessions()
        .transaction(&ta.transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.portal_bind_sha256,
        Some(k.p1.digest()),
        "digest unchanged by the lure"
    );

    // the callback for TA arrives with P2: no token exchange, TA consumed, retry offered
    let before = k.mock.completes();
    let out = k.callback(&sa, Some(&p2), None).await.unwrap();
    let CallbackOutcome::Interrupted {
        retry_ref,
        retry_allowed,
        depth,
    } = out
    else {
        panic!("expected Interrupted")
    };
    assert!(retry_allowed);
    assert_eq!(depth, 0);
    assert_eq!(k.mock.completes(), before, "no token exchange");
    let row = k
        .store
        .sessions()
        .transaction(&ta.transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert!(row.consumed_at.is_some());
    assert_eq!(row.consumed_reason.as_deref(), Some("portal_bind_mismatch"));
    assert_eq!(row.retry_bind_sha256, Some(p2.digest()));
    assert_eq!(retry_ref, row.txn_sha256);

    // POST /login/retry refusals: cookie P1, no cookie, another transaction
    for bad in [Some(&k.p1), None] {
        let e = k.svc.retry(&k.ctx(), &retry_ref, bad).await.unwrap_err();
        assert_eq!(reason_of(&e), "portal_bind_mismatch");
    }
    let other = k.start(APP, "/z", Some(&k.b1)).await;
    let e = k
        .svc
        .retry(&k.ctx(), &other.transaction.digest(), Some(&p2))
        .await
        .unwrap_err();
    assert_eq!(
        reason_of(&e),
        "portal_bind_mismatch",
        "only a transaction that failed with portal_bind_mismatch"
    );

    // with P2: a new transaction at depth + 1 for the same target, P2 recorded at its redirect
    let retry = k.svc.retry(&k.ctx(), &retry_ref, Some(&p2)).await.unwrap();
    assert_eq!(retry.location.host_str(), Some("idp.example.test"));
    let ta3: (String, i64) = k
        .store
        .conn()
        .query_row(
            "SELECT return_target, recovery_depth FROM login_txns WHERE recovery_depth = 1 AND consumed_at IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ta3, (format!("https://{APP}/admin/x"), 1));
    assert_eq!(
        k.count(&format!("SELECT COUNT(*) FROM login_txns WHERE recovery_depth=1 AND portal_bind_sha256 = x'{}' AND bind_sha256 = x'{}'", p2.digest(), k.b1.digest())),
        1
    );
    // the second callback (state of the new transaction) with P2 creates the session
    let state3 = Secret::new(
        retry
            .location
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state in the authorization url"),
    );
    let out = k.callback(&state3, Some(&p2), None).await.unwrap();
    let logged = k.logged(out, ta.transaction.clone());
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
    // TB's callback (P2) then reuses that session: same user, valid portal handle
    let out = k
        .callback(&sb, Some(&p2), Some(&logged.portal_handle))
        .await
        .unwrap();
    let CallbackOutcome::LoggedIn {
        reused_session,
        session_id,
        portal_handle,
        ..
    } = out
    else {
        panic!()
    };
    assert!(reused_session && portal_handle.is_none());
    assert_eq!(session_id, logged.session_id);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions"),
        1,
        "no second session"
    );
}

// ---- abuse cases ------------------------------------------------------------

#[tokio::test]
async fn s002_a1_replayed_callback_rejected() {
    let k = Kit::new().await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    k.callback(&state, Some(&k.p1), None).await.unwrap();
    let calls = k.mock.completes();
    let sessions = k.count("SELECT COUNT(*) FROM sessions");
    let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "txn_consumed");
    assert_eq!(k.mock.completes(), calls, "no token endpoint call");
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions"),
        sessions,
        "no new session"
    );
}

#[tokio::test]
async fn s002_a2_tampered_token_artifacts_rejected() {
    type Case = (&'static str, fn() -> ProviderError, &'static str);
    let cases: Vec<Case> = vec![
        (
            "wrong_nonce",
            || ProviderError::InvalidNonce,
            "invalid_nonce",
        ),
        (
            "wrong_aud",
            || ProviderError::InvalidAudience,
            "invalid_audience",
        ),
        (
            "invalid_signature",
            || ProviderError::InvalidSignature,
            "invalid_signature",
        ),
        (
            "expired_token",
            || ProviderError::TokenExpired,
            "token_expired",
        ),
    ];
    for (profile, make, code) in cases {
        let k = Kit::new().await;
        k.mock.set(move || Err(make()));
        let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
        let state = k.redirect(&started.transaction, &k.p1).await;
        let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
        assert_eq!(reason_of(&e), code, "{profile}");
        assert_eq!(
            k.mock.completes(),
            1,
            "{profile}: exactly one token request"
        );
        assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0, "{profile}");
        assert_eq!(k.count("SELECT COUNT(*) FROM users"), 0, "{profile}");
        // validation failures consume the transaction and record login.failed with the reason
        let failed = k.events(EventKind::LoginFailed).await;
        assert_eq!(failed.len(), 1, "{profile}");
        assert_eq!(failed[0].reason.map(|r| r.0), Some(code), "{profile}");
        assert_eq!(
            k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
            1,
            "{profile}"
        );
    }
    // wrong_state: a state that was never issued: no token request at all
    let k = Kit::new().await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let _ = k.redirect(&started.transaction, &k.p1).await;
    let bogus = hopae::crypto::random_token(&hopae::crypto::OsRng, 24);
    let e = k.callback(&bogus, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "invalid_state");
    assert_eq!(k.mock.completes(), 0);
    // the real transaction is untouched
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
        0
    );
}

#[tokio::test]
async fn s002_a3_concurrent_callbacks_single_session() {
    let k = Kit::new().await;
    *k.mock.delay.lock().unwrap() = std::time::Duration::from_millis(50);
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let (a, b) = tokio::join!(
        k.callback(&state, Some(&k.p1), None),
        k.callback(&state, Some(&k.p1), None)
    );
    let (ok, err): (Vec<_>, Vec<_>) = [a, b].into_iter().partition(|r| r.is_ok());
    assert_eq!(ok.len(), 1, "exactly one callback succeeds");
    assert_eq!(err.len(), 1);
    assert_eq!(reason_of(err[0].as_ref().unwrap_err()), "txn_consumed");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
    assert_eq!(k.count("SELECT COUNT(*) FROM handoff_codes"), 1);
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 1);
}

#[tokio::test]
async fn s002_a4_oversized_and_slow_provider_bounded() {
    // The provider (W1-C) bounds size and time; the session service's part is
    // that such a failure is reported and leaves the transaction usable.
    let makers: [fn() -> ProviderError; 2] = [
        || ProviderError::ProviderResponseTooLarge,
        || ProviderError::ProviderTimeout,
    ];
    for e in makers {
        let k = Kit::new().await;
        k.mock.set(move || Err(e()));
        let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
        let state = k.redirect(&started.transaction, &k.p1).await;
        let err = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
        assert!(["provider_response_too_large", "provider_timeout"].contains(&reason_of(&err)));
        assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(
            k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL"),
            0,
            "usable until its own expiry"
        );
        // the provider recovers and the same callback succeeds
        k.mock
            .set_identity("sub-1", "a@example.test", true, false, "Alice");
        k.callback(&state, Some(&k.p1), None).await.unwrap();
        assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
    }
}

#[tokio::test]
async fn s002_a5_login_csrf_rejected() {
    let k = Kit::new().await;
    // the attacker's transaction T9 with portal cookie P9; the victim holds nothing
    let t9 = k.start(APP, "/attacker", Some(&k.b1)).await;
    let p9 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let s9 = k.redirect(&t9.transaction, &p9).await;
    let e = k.callback(&s9, None, None).await.unwrap_err();
    assert_eq!(reason_of(&e), "portal_bind_mismatch");
    assert_eq!(k.mock.completes(), 0, "no token exchange");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
    // T9 is consumed: the attacker cannot retry it either
    let e = k.callback(&s9, Some(&p9), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "txn_consumed");
    assert_eq!(k.mock.completes(), 0);

    // a victim holding its own well-formed cookie: no token exchange, no session;
    // the transaction is consumed and only the interrupted page (retry) is offered
    let t8 = k.start(APP, "/attacker", Some(&k.b1)).await;
    let s8 = k.redirect(&t8.transaction, &p9).await;
    let out = k.callback(&s8, Some(&k.p1), None).await.unwrap();
    assert!(matches!(out, CallbackOutcome::Interrupted { .. }));
    assert_eq!(k.mock.completes(), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
    // a malformed cookie is not even a retry candidate
    let t7 = k.start(APP, "/attacker", Some(&k.b1)).await;
    let s7 = k.redirect(&t7.transaction, &p9).await;
    let junk = Secret::new("not a cookie".into());
    let e = k.callback(&s7, Some(&junk), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "portal_bind_mismatch");
}

#[tokio::test]
async fn s002_a6_provider_mixup_rejected() {
    let k = Kit::new().await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    // artifacts of provider `mock` presented on /callback/mock2
    let e = k
        .callback_on(&ProviderId::new("mock2"), &state, Some(&k.p1), None)
        .await
        .unwrap_err();
    assert_eq!(reason_of(&e), "provider_mismatch");
    assert_eq!(
        k.mock.completes() + k.mock2.completes(),
        0,
        "no token exchange"
    );
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
    // a token from another issuer on the right path is the provider's invalid_issuer
    let k = Kit::new().await;
    k.mock.set(|| Err(ProviderError::InvalidIssuer));
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "invalid_issuer");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
}

#[tokio::test]
async fn s002_a7_pkce_nonce_not_negotiable() {
    // a provider that cannot supply nonce and PKCE verifier is refused, not weakened
    let k = Kit::new().await;
    k.mock
        .omit_nonce
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let e = k
        .svc
        .begin_provider(&k.ctx(), &started.transaction, &k.mock_id(), Some(&k.p1))
        .await
        .unwrap_err();
    assert_eq!(reason_of(&e), "invalid_nonce");
    let row = k
        .store
        .sessions()
        .transaction(&started.transaction.digest())
        .await
        .unwrap()
        .unwrap();
    assert!(row.state_sha256.is_none(), "nothing was bound");
    // a token response without id_token is rejected with the provider's reason
    let k = Kit::new().await;
    k.mock.set(|| Err(ProviderError::IdTokenMissing));
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "id_token_missing");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
}

#[tokio::test]
async fn s002_a8_failure_pages_uniform() {
    // an invalid signature fails before any directory lookup, so the outcome
    // cannot depend on whether the account exists
    let mut seen = Vec::new();
    for existing in [true, false] {
        let k = Kit::new().await;
        if existing {
            k.login().await;
        }
        k.mock.set(|| Err(ProviderError::InvalidSignature));
        let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
        let state = k.redirect(&started.transaction, &k.p1).await;
        let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
        seen.push(format!("{e:?} / {}", e.reason().0));
    }
    assert_eq!(
        seen[0], seen[1],
        "identical failure for an existing and an unknown account"
    );
}

#[tokio::test]
async fn s002_a9_userinfo_subject_mismatch_rejected() {
    let k = Kit::new().await;
    // an existing user the attacker would like to be mapped onto
    let victim = k.login().await;
    let users = k.count("SELECT COUNT(*) FROM users");
    let identities = k.count("SELECT COUNT(*) FROM identities");
    let sessions = k.count("SELECT COUNT(*) FROM sessions");
    k.mock.set(|| Err(ProviderError::UserinfoSubjectMismatch));
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&started.transaction, &k.p1).await;
    let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(reason_of(&e), "userinfo_subject_mismatch");
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), users);
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), identities);
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), sessions);
    let failed = k.events(EventKind::LoginFailed).await;
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].reason.map(|r| r.0),
        Some("userinfo_subject_mismatch")
    );
    let _ = victim;
}
