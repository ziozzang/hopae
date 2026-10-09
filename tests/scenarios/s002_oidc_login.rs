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
    use hopae::event::types::{Event, EventKind, reasons};
    use hopae::identity::linking::LinkingPolicy;
    use hopae::identity::types::NormalizedEmail;
    use hopae::policy::types::{AppId, AppPolicy, ConfigSnapshot, Host, SessionPolicy};
    use hopae::provider::types::{
        AuthorizationRequest, CallbackQuery, Provider, ProviderError, ProviderHealth, ProviderId,
        ProviderIdentity, ProviderKind,
    };
    use hopae::session::{
        CallbackOutcome, Deps, ProviderLookup, RequestCtx, Service, ServiceConfig,
    };
    use hopae::store::types::*;
    use hopae::store::{Store, StoreResult};
    use hopae::verify::types::{
        BindAction, CallerAuth, CanonicalPath, Decision, DenyKind, EntryReturn, FetchSite, Handoff,
        KeySlot, Navigation, Scheme, VerifyContext, VerifyInput, VerifyLimits,
    };
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

    /// An emitter whose diagnostics go nowhere (the receiver is dropped; the
    /// drops are counted), for tests that drive the services in process.
    pub fn test_emitter(
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> (
        hopae::event::bus::Emitter,
        tokio::sync::mpsc::Receiver<hopae::event::types::Event>,
    ) {
        let (bus, rx) = hopae::event::bus::channel(64);
        let emitter = hopae::event::bus::Emitter::new(
            clock,
            rng,
            bus,
            Arc::new(hopae::event::sampling::Sampler::default()),
            Arc::new(hopae::event::prune::PruneTrigger::new(1000)),
            false,
        );
        (emitter, rx)
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
            auth_time: None,
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

    /// A created login transaction, as the verify engine answered it.
    pub struct StartedLogin {
        pub transaction: Secret,
        pub bind: BindAction,
        pub app_id: AppId,
    }

    impl std::fmt::Debug for StartedLogin {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StartedLogin")
                .field("app_id", &self.app_id)
                .finish_non_exhaustive()
        }
    }

    /// A redemption through the verify engine (the single owner of redemption,
    /// recovery and switch, ruling R-1), as the tests read it.
    #[derive(Debug)]
    pub enum RedeemResult {
        Minted {
            location: Url,
            handle: Secret,
            issued_aal: hopae::session::Aal,
            max_age: Duration,
        },
        AlreadyRedeemed {
            location: Url,
        },
        Login(StartedLogin),
        Switch {
            transaction: Secret,
        },
        Exhausted {
            depth: u32,
        },
        RateLimited {
            retry_after: Duration,
        },
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
        pub hooks: Option<Arc<hopae::store::StoreHooks>>,
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
                hooks: None,
            }
        }
    }

    pub struct Kit {
        pub store: Store,
        pub clock: Arc<TestClock>,
        pub svc: Service,
        /// The verify engine over the same store: the only creator of login
        /// and switch transactions and the only redeemer of codes.
        pub verify: VerifyContext,
        pub mock: Arc<FakeProvider>,
        pub mock2: Arc<FakeProvider>,
        /// `__Host-hopae_bind` on the application hosts and `__Host-hopae_portal` on the portal.
        pub b1: Secret,
        pub p1: Secret,
        pub opts: Opts,
        /// The diagnostic events the service and the engine emitted.
        diag: std::sync::Mutex<tokio::sync::mpsc::Receiver<Event>>,
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
                opts.hooks.clone(),
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
            let (emitter, diag) = test_emitter(clock.clone(), rng.clone());
            let svc = Service::new(Deps {
                directory: store.directory(),
                sessions: store.sessions(),
                events: store.events(),
                emitter: emitter.clone(),
                clock: clock.clone(),
                rng: rng.clone(),
                snapshot: snapshot.clone(),
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
            let limits = VerifyLimits {
                max_recoveries: opts.max_recoveries,
                txn_per_ip_per_minute: opts.txn_per_ip,
                txn_max_rows: opts.txn_max_rows,
                handoff_failures_per_minute: opts.failures_per_minute,
                ..VerifyLimits::default()
            };
            let mut verify = VerifyContext::new(
                store.directory(),
                store.sessions(),
                clock.clone(),
                rng,
                snapshot,
                limits,
            );
            // The engine reports diagnostics (`txn.evicted`) through the same emitter.
            verify.emitter = Some(emitter);
            Kit {
                diag: std::sync::Mutex::new(diag),
                store,
                clock,
                svc,
                verify,
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
                client_request_id: None,
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

        /// A verify request as the adapter would hand it to the engine.
        pub fn verify_input(
            &self,
            addr: &str,
            target: &Url,
            code: Option<&Secret>,
            bind: Option<&Secret>,
            handle: Option<&Secret>,
        ) -> VerifyInput {
            let clean = hopae::gateway::recognition::clean_target(target);
            VerifyInput {
                canonical_path: CanonicalPath::new(clean.path().to_string()),
                port: clean.port_or_known_default().unwrap_or(443),
                proto: if clean.scheme() == "http" {
                    Scheme::Http
                } else {
                    Scheme::Https
                },
                host: host(clean.host_str().unwrap_or("")),
                original_url: clean,
                client_ip: ip(addr),
                method: http::Method::GET,
                route_id: None,
                cookie_handle: handle.cloned(),
                bind_cookie: bind.cloned(),
                user_agent: Some(UA.into()),
                navigation: Navigation::Document,
                accepts_html: true,
                fetch_site: FetchSite::Unknown,
                entry_return: EntryReturn::Absent,
                handoff: code.map_or(Handoff::None, |c| Handoff::Code(c.clone())),
                contract: 1,
                caller: CallerAuth::Keyed {
                    which: KeySlot::Current,
                },
                request_id: "req-verify".into(),
            }
        }

        /// Flow 1: a login transaction for `https://<host><path_query>` from `IP`
        /// (the verify engine's unauthenticated `302`).
        pub async fn start(
            &self,
            host_name: &str,
            path_query: &str,
            bind: Option<&Secret>,
        ) -> StartedLogin {
            match self
                .decide_login(IP, &url(&format!("https://{host_name}{path_query}")), bind)
                .await
            {
                RedeemResult::Login(s) => s,
                other => panic!("expected a login transaction, got {other:?}"),
            }
        }

        async fn decide_login(
            &self,
            addr: &str,
            target: &Url,
            bind: Option<&Secret>,
        ) -> RedeemResult {
            self.decide(self.verify_input(addr, target, None, bind, None))
                .await
        }

        pub async fn decide(&self, input: VerifyInput) -> RedeemResult {
            let app = self
                .verify
                .snapshot
                .load()
                .app_for_host(&input.host)
                .map(|a| a.app_id.clone())
                .unwrap_or_else(|| AppId::new("?"));
            match hopae::verify::decide(&self.verify, input).await {
                Decision::Login {
                    transaction: Some(transaction),
                    bind,
                    ..
                } => RedeemResult::Login(StartedLogin {
                    transaction,
                    bind,
                    app_id: app,
                }),
                Decision::Handoff {
                    location,
                    handle,
                    issued_aal,
                    max_age,
                } => RedeemResult::Minted {
                    location,
                    handle,
                    issued_aal,
                    max_age,
                },
                Decision::CleanRedirect { location } => RedeemResult::AlreadyRedeemed { location },
                Decision::Switch { transaction } => RedeemResult::Switch { transaction },
                Decision::Deny {
                    reason,
                    kind: DenyKind::RateLimited { retry_after },
                } if reason == reasons::RATE_LIMITED => RedeemResult::RateLimited { retry_after },
                Decision::Deny { reason, .. } if reason == reasons::HANDOFF_RECOVERY_EXHAUSTED => {
                    RedeemResult::Exhausted {
                        depth: self.opts.max_recoveries,
                    }
                }
                Decision::Deny { reason, .. } => panic!("denied: {}", reason.0),
                other => panic!(
                    "unexpected decision {:?}",
                    hopae::gateway::hangang::decision_label(&other)
                ),
            }
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
            self.decide(self.verify_input(addr, target, Some(code), bind, handle))
                .await
        }

        pub fn count(&self, sql: &str) -> i64 {
            self.store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }

        pub fn text(&self, sql: &str) -> Option<String> {
            self.store.conn().query_row(sql, [], |r| r.get(0)).ok()
        }

        /// Rows reported evicted so far by `txn.evicted` diagnostics (the sum of their counts).
        pub fn evicted_reported(&self) -> i64 {
            let mut rx = self.diag.lock().unwrap();
            let mut total = 0;
            while let Ok(ev) = rx.try_recv() {
                if ev.kind == EventKind::TxnEvicted {
                    total += ev.to_json()["attrs"]["count"].as_i64().unwrap_or(0);
                }
            }
            total
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

    /// The clean return target a handoff location stands for. Every handoff is
    /// delivered to the host's login entry point, `/_hopae/login?return=<target>
    /// &_hopae_handoff=<code>` (ADR-0015); the target is its `return`.
    pub fn strip_handoff(location: &Url) -> Url {
        assert_eq!(location.path(), "/_hopae/login", "{location}");
        let ret = location
            .query_pairs()
            .find(|(k, _)| k == "return")
            .map(|(_, v)| v.into_owned())
            .expect("return parameter");
        let mut origin = location.clone();
        origin.set_path("/");
        origin.set_query(None);
        origin.join(&ret).expect("return resolves on the origin")
    }

    /// The location without the reserved parameter, as the pre-ADR-0015 wire had it.
    #[allow(dead_code)]
    pub fn strip_handoff_param(location: &Url) -> Url {
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
    // ADR-0015: delivered to the login entry point, carrying the target.
    assert_eq!(location.path(), "/_hopae/login");
    assert_eq!(strip_handoff(&location).path(), "/admin/x");
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

/// ADR-0015 review: `txn.max_rows` also bounds the link transaction (written
/// after authentication, so without the per-address cap).
#[tokio::test]
async fn link_transaction_respects_max_rows_at_capacity() {
    let k = Kit::with(Opts {
        txn_max_rows: 1,
        ..Opts::default()
    })
    .await;
    existing_user_with_email(&k, false).await;
    let started = k.start(APP, "/admin/x", Some(&k.b1)).await;
    assert_eq!(k.count("SELECT COUNT(*) FROM login_txns"), 1, "at capacity");
    let state = k.redirect(&started.transaction, &k.p1).await;
    let out = k.callback(&state, Some(&k.p1), None).await.unwrap();
    assert!(
        matches!(out, CallbackOutcome::LinkRequired { .. }),
        "{out:?}"
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns"),
        1,
        "the link row evicted the dead login row instead of exceeding the bound"
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE purpose = 'link'"),
        1
    );
    assert_eq!(
        k.evicted_reported(),
        1,
        "the eviction made by the link insert is reported as txn.evicted"
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
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&first.portal_handle),
            None,
            false,
        )
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
    assert_eq!(location.path(), "/_hopae/login");
    assert_eq!(strip_handoff(&location).path(), "/");
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
        .sso_or_chooser(
            &k.ctx(),
            &t2.transaction,
            Some(&first.portal_handle),
            None,
            false,
        )
        .await;
    assert_eq!(reason_of(&again.unwrap_err()), "txn_consumed");
    // without a handle the same visit lists providers
    let t3 = k.start(OTHER, "/", Some(&b2)).await;
    let entry = k
        .svc
        .sso_or_chooser(&k.ctx(), &t3.transaction, None, None, false)
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
        .sso_or_chooser(&k.ctx(), &t3.transaction, Some(&bogus), None, false)
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
    // R-4: the retry is single-use per consumed transaction, whatever the cookie.
    let again = k
        .svc
        .retry(&k.ctx(), &retry_ref, Some(&p2))
        .await
        .unwrap_err();
    assert_eq!(
        reason_of(&again),
        "txn_consumed",
        "a second POST is refused"
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE recovery_depth = 1"),
        1,
        "no second transaction"
    );
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

/// One portal visit (a login transaction for `OTHER`) presenting `portal_handle`.
async fn g7_portal_visit(k: &Kit, portal_handle: &Secret) -> LoginEntry {
    let b = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let t = k.start(OTHER, "/", Some(&b)).await;
    k.svc
        .sso_or_chooser(&k.ctx(), &t.transaction, Some(portal_handle), None, false)
        .await
        .unwrap()
}

fn g7_portal_handle_state(k: &Kit, h: &Secret) -> (Option<String>, i64) {
    k.store
        .conn()
        .query_row(
            "SELECT revoked_reason, last_seen_at FROM session_handles WHERE handle_sha256 = ?1",
            [h.digest().0.to_vec()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// G7-C03 / G7-IDP-06: portal visits keep the portal handle alive (activity
/// is recorded and coalesced to 30 s), so continuous SSO never lapses.
#[tokio::test]
async fn g7_c03_portal_activity_keeps_the_portal_handle_alive() {
    let k = Kit::new().await;
    let first = k.login().await;
    let t0 = T0 / 1000;
    // Every 8 h, inside the default 12 h portal idle: each visit must SSO.
    for i in 1..=4u64 {
        k.advance(8 * 3600);
        let entry = g7_portal_visit(&k, &first.portal_handle).await;
        assert!(
            matches!(entry, LoginEntry::Sso { .. }),
            "visit {i} at +{}h must still be single sign-on, got {entry:?}",
            8 * i
        );
        assert_eq!(
            g7_portal_handle_state(&k, &first.portal_handle).1,
            t0 + (8 * 3600 * i) as i64,
            "the portal handle records the activity"
        );
    }
    // Coalescing: a second visit within 30 s writes nothing.
    let seen = g7_portal_handle_state(&k, &first.portal_handle).1;
    k.advance(10);
    assert!(matches!(
        g7_portal_visit(&k, &first.portal_handle).await,
        LoginEntry::Sso { .. }
    ));
    assert_eq!(g7_portal_handle_state(&k, &first.portal_handle).1, seen);
}

/// G7-C03 / G7-IDP-06: an expired portal handle is revoked (idle), an expired
/// session is terminated, each with its event; the provider is consulted again.
#[tokio::test]
async fn g7_c03_portal_expiry_applies_state_transitions() {
    // Handle idle (12 h) while the session (24 h) runs on.
    let k = Kit::new().await;
    let first = k.login().await;
    k.advance(13 * 3600);
    let entry = g7_portal_visit(&k, &first.portal_handle).await;
    assert!(matches!(entry, LoginEntry::Chooser { .. }), "{entry:?}");
    assert_eq!(
        g7_portal_handle_state(&k, &first.portal_handle)
            .0
            .as_deref(),
        Some("idle")
    );
    let ev = k.events(EventKind::HandleRevoked).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::IDLE));
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions WHERE terminated_at IS NOT NULL"),
        0
    );

    // Session idle (24 h): the session is terminated.
    let k = Kit::new().await;
    let first = k.login().await;
    k.advance(25 * 3600);
    let entry = g7_portal_visit(&k, &first.portal_handle).await;
    assert!(matches!(entry, LoginEntry::Chooser { .. }), "{entry:?}");
    assert_eq!(
        k.text("SELECT terminated_reason FROM sessions").as_deref(),
        Some("idle")
    );
    let ev = k.events(EventKind::SessionTerminated).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].reason, Some(reasons::IDLE));
}

/// G7-C07: portal retries are counted against the transaction's application
/// IP (the provenance every replacement is inserted with), so a split
/// portal/application IP cannot dodge `txn.per_ip_per_minute`.
#[tokio::test]
async fn g7_c07_retries_count_against_the_application_ip() {
    const PORTAL_IP: &str = "198.51.100.77";
    let k = Kit::with(Opts {
        txn_per_ip: 5,
        ..Opts::default()
    })
    .await;
    // binding.ip=off: the portal may complete from another address.
    let mut snap = (**k.verify.snapshot.load()).clone();
    for a in snap.apps.iter_mut() {
        a.binding.ip = hopae::policy::types::IpBinding::Off;
    }
    k.verify.snapshot.store(Arc::new(snap));

    let p2 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let mut refs = Vec::new();
    // Two batches a minute apart: each within the creation cap, ten live
    // transactions in all, each interrupted by a portal-cookie change.
    for batch in 0..2 {
        if batch == 1 {
            k.advance(61);
        }
        for i in 0..5 {
            let t = k.start(APP, &format!("/p{batch}{i}"), Some(&k.b1)).await;
            let state = k.redirect(&t.transaction, &k.p1).await;
            let out = k
                .svc
                .complete_callback(
                    &k.ctx_ip(PORTAL_IP),
                    &k.mock_id(),
                    CallbackQuery {
                        code: Some("AC1".into()),
                        state: Some(state.expose().to_string()),
                        error: None,
                        error_description: None,
                    },
                    Some(&p2),
                    None,
                )
                .await
                .unwrap();
            let CallbackOutcome::Interrupted { retry_ref, .. } = out else {
                panic!("expected Interrupted, got {out:?}")
            };
            refs.push(retry_ref);
        }
    }
    // A minute later no transaction of the application IP is inside the window.
    k.advance(61);
    let mut admitted = 0;
    let mut limited = 0;
    for r in &refs {
        match k.svc.retry(&k.ctx_ip(PORTAL_IP), r, Some(&p2)).await {
            Ok(_) => admitted += 1,
            Err(SessionError::RateLimited { .. }) => limited += 1,
            Err(e) => panic!("unexpected retry error: {e:?}"),
        }
    }
    assert_eq!(
        (admitted, limited),
        (5, 5),
        "the cap of 5 per minute applies to the application IP of the replacements"
    );
}

fn g7_set_provider_row(k: &Kit, sql_set: &str) {
    k.store
        .conn()
        .execute(
            &format!("UPDATE providers SET {sql_set} WHERE provider_id = 'mock'"),
            [],
        )
        .unwrap();
}

/// G7-IDP-01: a provider disabled (or tombstoned) in the database while
/// Hopae keeps running stops authenticating: no flow begins, no token
/// exchange happens, no identity or session is written.
#[tokio::test]
async fn g7_idp01_live_provider_disable_stops_authentication() {
    for set in ["enabled = 0", "deleted_at = 1"] {
        // Disabled before the callback.
        let k = Kit::new().await;
        let t = k.start(APP, "/admin/x", Some(&k.b1)).await;
        let state = k.redirect(&t.transaction, &k.p1).await;
        g7_set_provider_row(&k, set);
        let completes = k.mock.completes();
        let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
        assert_eq!(e.reason().0, "provider_disabled", "{set}");
        assert_eq!(k.mock.completes(), completes, "{set}: no token exchange");
        assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(k.count("SELECT COUNT(*) FROM users"), 0);
        assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 0);

        // A new flow does not begin either.
        let t2 = k.start(APP, "/admin/y", Some(&k.b1)).await;
        let e = k
            .svc
            .begin_provider(&k.ctx(), &t2.transaction, &k.mock_id(), Some(&k.p1))
            .await
            .unwrap_err();
        assert_eq!(e.reason().0, "provider_disabled", "{set}: begin");
    }

    // Disabled while the token exchange is in flight.
    let k = Arc::new(Kit::new().await);
    let t = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    *k.mock.delay.lock().unwrap() = std::time::Duration::from_millis(300);
    let kk = k.clone();
    let p1 = k.p1.clone();
    let st = state.clone();
    let cb = tokio::spawn(async move { kk.callback(&st, Some(&p1), None).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    g7_set_provider_row(&k, "enabled = 0");
    let e = cb.await.unwrap().unwrap_err();
    assert_eq!(e.reason().0, "provider_disabled", "during the exchange");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 0);
}

/// G7-IDP-02: a non-empty `allowed_email_domains` admits only a verified
/// address; an unverified claim for an allowed domain creates nothing.
#[tokio::test]
async fn g7_idp02_unverified_email_does_not_pass_the_domain_allowlist() {
    let k = Kit::with(Opts {
        allowed_domains: vec!["corp.test".into()],
        ..Opts::default()
    })
    .await;
    k.mock
        .set_identity("attacker", "chosen@corp.test", false, false, "Mallory");
    let t = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    let e = k.callback(&state, Some(&k.p1), None).await.unwrap_err();
    assert_eq!(e.reason().0, "email_domain_not_allowed");
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);

    // The same address, verified by the provider, is admitted.
    k.mock
        .set_identity("alice", "chosen@corp.test", true, false, "Alice");
    let t = k.start(APP, "/admin/y", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    assert!(k.callback(&state, Some(&k.p1), None).await.is_ok());
}

/// G7-IDP-04: two concurrent callbacks for distinct subjects asserting the
/// same verified email produce one user; the loser meets `link_required`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g7_idp04_concurrent_same_email_distinct_subjects_link_required() {
    let hooks = Arc::new(hopae::store::StoreHooks::new());
    let k = Arc::new(
        Kit::with(Opts {
            hooks: Some(hooks.clone()),
            ..Opts::default()
        })
        .await,
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = calls.clone();
    k.mock.set(move || {
        let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ident(
            &format!("sub-race-{n}"),
            "dup@example.test",
            true,
            false,
            "Dup",
        ))
    });
    let mut states = Vec::new();
    for path in ["/a", "/b"] {
        let t = k.start(APP, path, Some(&k.b1)).await;
        states.push(k.redirect(&t.transaction, &k.p1).await);
    }
    // Hold the first user-creating commit so that both callbacks resolve
    // against an empty directory before either user exists.
    hooks.set_gate("create_user", true);
    let handles: Vec<_> = states
        .into_iter()
        .map(|st| {
            let k = k.clone();
            let p1 = k.p1.clone();
            tokio::spawn(async move { k.callback(&st, Some(&p1), None).await })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    hooks.set_gate("create_user", false);
    let mut logged_in = 0;
    let mut link_required = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(CallbackOutcome::LoggedIn { .. }) => logged_in += 1,
            Ok(CallbackOutcome::LinkRequired { .. }) => link_required += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        k.count("SELECT COUNT(*) FROM users WHERE primary_email = 'dup@example.test'"),
        1,
        "one owner of the address"
    );
    assert_eq!((logged_in, link_required), (1, 1));
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 1);
}

/// G7-C03 (pass 2): the touch-coalescing window never lets a handle idle out.
/// With a 20 s portal idle policy and a visit every 5 s the portal handle
/// stays alive indefinitely.
#[tokio::test]
async fn g7_c03_short_idle_policy_is_kept_alive_by_frequent_visits() {
    let k = Kit::new().await;
    let first = k.login().await;
    let mut snap = (**k.verify.snapshot.load()).clone();
    snap.default_app.session.idle = std::time::Duration::from_secs(20);
    k.verify.snapshot.store(Arc::new(snap));
    for i in 1..=24u32 {
        k.advance(5);
        let entry = g7_portal_visit(&k, &first.portal_handle).await;
        assert!(
            matches!(entry, LoginEntry::Sso { .. }),
            "visit {i} at +{}s must be single sign-on, got {entry:?}",
            5 * i
        );
    }
}

/// G7-C07 (pass 2): counting and admission are one atomic step, so parallel
/// retries never exceed `txn.per_ip_per_minute`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn g7_c07_parallel_retries_never_exceed_the_cap() {
    const PORTAL_IP: &str = "198.51.100.77";
    let k = Arc::new(
        Kit::with(Opts {
            txn_per_ip: 5,
            ..Opts::default()
        })
        .await,
    );
    let mut snap = (**k.verify.snapshot.load()).clone();
    for a in snap.apps.iter_mut() {
        a.binding.ip = hopae::policy::types::IpBinding::Off;
    }
    k.verify.snapshot.store(Arc::new(snap));
    let p2 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let mut refs = Vec::new();
    for batch in 0..4 {
        if batch > 0 {
            k.advance(61);
        }
        for i in 0..5 {
            let t = k.start(APP, &format!("/p{batch}{i}"), Some(&k.b1)).await;
            let state = k.redirect(&t.transaction, &k.p1).await;
            let out = k
                .svc
                .complete_callback(
                    &k.ctx_ip(PORTAL_IP),
                    &k.mock_id(),
                    CallbackQuery {
                        code: Some("AC1".into()),
                        state: Some(state.expose().to_string()),
                        error: None,
                        error_description: None,
                    },
                    Some(&p2),
                    None,
                )
                .await
                .unwrap();
            let CallbackOutcome::Interrupted { retry_ref, .. } = out else {
                panic!("expected Interrupted")
            };
            refs.push(retry_ref);
        }
    }
    k.advance(61);
    let tasks: Vec<_> = refs
        .into_iter()
        .map(|r| {
            let (k, p2) = (k.clone(), p2.clone());
            tokio::spawn(async move { k.svc.retry(&k.ctx_ip(PORTAL_IP), &r, Some(&p2)).await })
        })
        .collect();
    let mut admitted = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => admitted += 1,
            Err(SessionError::RateLimited { .. }) => {}
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }
    assert_eq!(admitted, 5, "never above the cap of 5 per minute");
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE created_at >= (SELECT MAX(created_at) FROM login_txns)"),
        5
    );
}

/// G7-IDP-01 (pass 2): a disable that commits after the callback's last
/// provider-row read but before the identity/session write transaction is
/// still caught, by the predicate inside that transaction. The store stall
/// hook holds `create_user` after the last read and before its transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g7_idp01_disable_between_the_last_read_and_the_write() {
    let hooks = Arc::new(hopae::store::StoreHooks::new());
    let k = Arc::new(
        Kit::with(Opts {
            hooks: Some(hooks.clone()),
            ..Opts::default()
        })
        .await,
    );
    let t = k.start(APP, "/admin/x", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    hooks.set_stall(500);
    let (kk, p1, st) = (k.clone(), k.p1.clone(), state.clone());
    let cb = tokio::spawn(async move { kk.callback(&st, Some(&p1), None).await });
    // `create_user` has been called (so every provider-row read is behind us)
    // and is waiting out the stall: now the operator disables the provider.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while hooks.calls().get("create_user").copied().unwrap_or(0) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "create_user never called"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    g7_set_provider_row(&k, "enabled = 0");
    let e = cb.await.unwrap().unwrap_err();
    assert_eq!(e.reason().0, "provider_disabled");
    assert_eq!(k.count("SELECT COUNT(*) FROM users"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM identities"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), 0);

    // The session write itself is guarded too (existing identity, no create_user).
    hooks.set_stall(0);
    g7_set_provider_row(&k, "enabled = 1");
    let t = k.start(APP, "/admin/y", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    k.callback(&state, Some(&k.p1), None).await.unwrap();
    k.advance(5);
    let t = k.start(APP, "/admin/z", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    hooks.set_stall(500);
    let sessions_before = k.count("SELECT COUNT(*) FROM sessions");
    let (kk, p1, st) = (k.clone(), k.p1.clone(), state.clone());
    let cb = tokio::spawn(async move { kk.callback(&st, Some(&p1), None).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while hooks.calls().get("create_session").copied().unwrap_or(0) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "create_session never called"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    g7_set_provider_row(&k, "enabled = 0");
    let e = cb.await.unwrap().unwrap_err();
    assert_eq!(e.reason().0, "provider_disabled");
    assert_eq!(k.count("SELECT COUNT(*) FROM sessions"), sessions_before);
}

/// G7-IDP-01 (pass 3): the session-reuse completion (existing identity, valid
/// portal handle of the same user) consumes the transaction in a write that
/// also checks the provider row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g7_idp01_reuse_path_checks_the_provider_in_its_write() {
    let hooks = Arc::new(hopae::store::StoreHooks::new());
    let k = Arc::new(
        Kit::with(Opts {
            hooks: Some(hooks.clone()),
            ..Opts::default()
        })
        .await,
    );
    let first = k.login().await;
    k.advance(5);
    let t = k.start(APP, "/admin/y", Some(&k.b1)).await;
    let state = k.redirect(&t.transaction, &k.p1).await;
    let baseline = hooks
        .calls()
        .get("consume_transaction")
        .copied()
        .unwrap_or(0);
    hooks.set_stall(500);
    let (kk, p1, h, st) = (
        k.clone(),
        k.p1.clone(),
        first.portal_handle.clone(),
        state.clone(),
    );
    let cb = tokio::spawn(async move { kk.callback(&st, Some(&p1), Some(&h)).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while hooks
        .calls()
        .get("consume_transaction")
        .copied()
        .unwrap_or(0)
        <= baseline
    {
        assert!(
            std::time::Instant::now() < deadline,
            "reuse consume never called"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    g7_set_provider_row(&k, "enabled = 0");
    let e = cb.await.unwrap().unwrap_err();
    assert_eq!(e.reason().0, "provider_disabled");
    assert_eq!(
        k.count("SELECT COUNT(*) FROM login_txns WHERE consumed_at IS NOT NULL AND consumed_reason='completed'"),
        1,
        "only the first login completed"
    );
}

/// G7-C07 (pass 3): eviction must not erase rate-limit evidence. With
/// `txn.max_rows = 5` and `per_ip_per_minute = 5`, five recent interrupted
/// transactions exhaust the cap: retrying them admits nothing.
#[tokio::test]
async fn g7_c07_eviction_does_not_erase_admission_history() {
    const PORTAL_IP: &str = "198.51.100.77";
    let k = Kit::with(Opts {
        txn_per_ip: 5,
        txn_max_rows: 5,
        ..Opts::default()
    })
    .await;
    let mut snap = (**k.verify.snapshot.load()).clone();
    for a in snap.apps.iter_mut() {
        a.binding.ip = hopae::policy::types::IpBinding::Off;
    }
    k.verify.snapshot.store(Arc::new(snap));
    let p2 = hopae::crypto::random_token(&hopae::crypto::OsRng, 16);
    let mut refs = Vec::new();
    for i in 0..5 {
        let t = k.start(APP, &format!("/p{i}"), Some(&k.b1)).await;
        let state = k.redirect(&t.transaction, &k.p1).await;
        let out = k
            .svc
            .complete_callback(
                &k.ctx_ip(PORTAL_IP),
                &k.mock_id(),
                CallbackQuery {
                    code: Some("AC1".into()),
                    state: Some(state.expose().to_string()),
                    error: None,
                    error_description: None,
                },
                Some(&p2),
                None,
            )
            .await
            .unwrap();
        let CallbackOutcome::Interrupted { retry_ref, .. } = out else {
            panic!("expected Interrupted")
        };
        refs.push(retry_ref);
    }
    let mut admitted = 0;
    for r in &refs {
        match k.svc.retry(&k.ctx_ip(PORTAL_IP), r, Some(&p2)).await {
            Ok(_) => admitted += 1,
            Err(SessionError::RateLimited { .. }) => {}
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }
    assert_eq!(
        admitted, 0,
        "five creations in this minute already used the cap"
    );
}
