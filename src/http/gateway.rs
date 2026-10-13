//! The gateway listener: `GET /_hopae/verify`. Wire details live in
//! `crate::gateway::hangang`; this module owns the caller-key check, the
//! concurrency limit, the verify budget and the call into the core.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use tokio::sync::Semaphore;

use crate::app::CallerKeys;
use crate::event::bus::Emitter;
use crate::event::types::{Reason, reasons};
use crate::gateway::hangang::{self, GatewayConfig, RenderEnv};
use crate::http::denials::{self, DenialCounters};
use crate::telemetry::counters;
use crate::verify::types::{Decision, DenyKind, Navigation, VerifyContext};

/// Increment a named counter with labels. The default does nothing; the
/// process wiring installs `telemetry::counters::inc`.
pub type CounterFn = Arc<dyn Fn(&str, &[(&str, &str)]) + Send + Sync>;

/// Shared state of the gateway listener.
pub struct GatewayState {
    pub cfg: GatewayConfig,
    pub ctx: VerifyContext,
    callers: Arc<CallerKeys>,
    limit: Arc<Semaphore>,
    counters: CounterFn,
    emitter: Option<Emitter>,
    next_id: AtomicU64,
    id_salt: RandomState,
    authentication_gateway:
        Option<Arc<arc_swap::ArcSwap<crate::auth_gateway::authority::Snapshot>>>,
}

impl GatewayState {
    /// `max_concurrent` is `limits.gateway_max_concurrent`. `callers` is the
    /// one caller-key implementation (`app::CallerKeys`); `emitter` receives a
    /// sampled `verify.denied` for every denial (none in adapter unit tests).
    pub fn new(
        cfg: GatewayConfig,
        ctx: VerifyContext,
        callers: Arc<CallerKeys>,
        max_concurrent: u32,
        counters: Option<CounterFn>,
        emitter: Option<Emitter>,
    ) -> Arc<Self> {
        Arc::new(GatewayState {
            cfg,
            ctx,
            callers,
            limit: Arc::new(Semaphore::new(max_concurrent as usize)),
            counters: counters.unwrap_or_else(|| Arc::new(|_, _| {})),
            emitter,
            next_id: AtomicU64::new(0),
            id_salt: RandomState::new(),
            authentication_gateway: None,
        })
    }

    pub fn with_authentication_gateway(
        mut self: Arc<Self>,
        runtime: crate::auth_gateway::runtime::Runtime,
    ) -> anyhow::Result<Arc<Self>> {
        Arc::get_mut(&mut self)
            .ok_or_else(|| anyhow::anyhow!("authentication gateway state is already shared"))?
            .authentication_gateway = Some(Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::auth_gateway::authority::Snapshot {
                revision: 0,
                runtime: Some(runtime),
            },
        )));
        Ok(self)
    }

    pub fn with_authentication_authority(
        mut self: Arc<Self>,
        reader: Arc<arc_swap::ArcSwap<crate::auth_gateway::authority::Snapshot>>,
    ) -> anyhow::Result<Arc<Self>> {
        Arc::get_mut(&mut self)
            .ok_or_else(|| anyhow::anyhow!("authentication gateway state is already shared"))?
            .authentication_gateway = Some(reader);
        Ok(self)
    }

    fn count(&self, name: &str, labels: &[(&str, &str)]) {
        (self.counters)(name, labels);
    }

    /// A correlation id that does not draw from the seeded random source.
    fn request_id(&self) -> String {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("r_{:016x}", self.id_salt.hash_one(n))
    }

    fn count_decision(&self, decision: &Decision) {
        let (name, reason) = hangang::decision_label(decision);
        self.count(
            counters::VERIFY_DECISIONS_TOTAL,
            &[("decision", name), ("reason", reason)],
        );
        if matches!(decision, Decision::Deny { reason: r, .. } if *r == reasons::STORE_UNAVAILABLE)
        {
            self.count(counters::STORE_ERRORS_TOTAL, &[]);
        }
    }

    /// Record a denial (counted always, one sampled event per scope and reason).
    fn denied(
        &self,
        decision: &Decision,
        cause: Option<Reason>,
        client_ip: Option<std::net::IpAddr>,
        session: Option<&crate::session::types::SessionId>,
        app: Option<&crate::policy::types::AppId>,
        request_id: &str,
    ) {
        denials::record_denial(
            self.emitter.as_ref(),
            &DenialCounters::GATEWAY,
            decision,
            cause,
            client_ip,
            session,
            app,
            request_id,
        );
    }
}

/// Router of the gateway listener.
pub fn router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route(hangang::VERIFY_PATH, get(verify))
        .with_state(state)
}

async fn verify(State(st): State<Arc<GatewayState>>, headers: HeaderMap) -> Response {
    let request_id = st.request_id();
    // Denials before the forwarded client address is parsed have no client
    // to attribute them to (the TCP peer is the gateway itself).
    let peer_ip: Option<std::net::IpAddr> = None;

    // 1. Caller key, before the permit and before any other header is read:
    //    an unauthenticated request never takes a permit.
    let caller = match hangang::authenticate(&st.callers, &headers, &request_id) {
        Ok(c) => c,
        Err(rej) => {
            st.count_decision(&rej.decision);
            st.denied(&rej.decision, None, peer_ip, None, None, &request_id);
            return hangang::render(rej.decision, Navigation::Other, &rej.env, &st.cfg);
        }
    };

    // 2. Bounded concurrency.
    let Ok(_permit) = st.limit.clone().try_acquire_owned() else {
        st.count(counters::VERIFY_OVERLOADED_TOTAL, &[]);
        let decision = Decision::Deny {
            reason: reasons::OVERLOADED,
            kind: DenyKind::Unavailable {
                retry_after: Duration::from_secs(1),
            },
        };
        st.count_decision(&decision);
        st.denied(&decision, None, peer_ip, None, None, &request_id);
        let env = RenderEnv {
            request_id,
            ..RenderEnv::default()
        };
        return hangang::render(decision, Navigation::Other, &env, &st.cfg);
    };

    let parsed = match hangang::parse(&st.cfg, &headers, request_id.clone(), caller) {
        Ok(p) => p,
        Err(rej) => {
            if let Some(metric) = rej.metric {
                st.count(metric, &[]);
            }
            st.count_decision(&rej.decision);
            st.denied(&rej.decision, None, peer_ip, None, None, &request_id);
            return hangang::render(rej.decision, Navigation::Other, &rej.env, &st.cfg);
        }
    };
    let (input, env) = (parsed.input, parsed.env);
    let authority = st
        .authentication_gateway
        .as_ref()
        .map(|reader| reader.load_full());
    // A presented service credential never falls back after its profile was removed.
    if let Some(snapshot) = &authority
        && matches!(
            input.canonical_path.reserved(),
            crate::verify::types::Reserved::No
        )
        && headers.contains_key(axum::http::header::AUTHORIZATION)
        && snapshot
            .runtime
            .as_ref()
            .is_none_or(|runtime| !runtime.handles(input.host.as_str(), input.port))
    {
        return hangang::service_identity::response(None, &request_id);
    }
    if let Some(runtime) = authority
        .as_ref()
        .and_then(|snapshot| snapshot.runtime.as_ref())
        && runtime.handles(input.host.as_str(), input.port)
        && matches!(
            input.canonical_path.reserved(),
            crate::verify::types::Reserved::No
        )
    {
        let presented = hangang::service_identity::bearer(&headers);
        let fallback = matches!(presented, Ok(None))
            && runtime.session_fallback(input.host.as_str(), input.port);
        if !fallback {
            let result = match presented {
                Ok(token) => tokio::time::timeout(
                    st.ctx.limits.budget,
                    runtime.authenticate_async(
                        input.host.as_str(),
                        input.port,
                        token,
                        input.client_ip,
                        st.ctx.clock.now().0.max(0) as u64,
                    ),
                )
                .await
                .unwrap_or(Err(crate::auth_gateway::runtime::Error::Unavailable)),
                Err(_) => Err(crate::auth_gateway::runtime::Error::Invalid),
            };
            let unavailable = matches!(
                result,
                Err(crate::auth_gateway::runtime::Error::Unavailable)
            );
            let evidence = result.ok();
            st.count(
                "hopae_authentication_gateway_total",
                &[(
                    "decision",
                    if evidence.is_some() {
                        "authenticated"
                    } else {
                        "denied"
                    },
                )],
            );
            if unavailable {
                return hangang::service_identity::unavailable(&request_id);
            }
            if evidence.is_some() {
                let policy = st.ctx.snapshot.load_full();
                let refused = match crate::policy::apps::resolve(&policy, &input.host) {
                    Err(reason) => Some(reason),
                    Ok(app)
                        if app.step_up.iter().any(|rule| {
                            crate::policy::step_up::rule_matches(
                                rule,
                                input.canonical_path.as_str(),
                            )
                        }) =>
                    {
                        Some(reasons::STEP_UP_REQUIRED)
                    }
                    Ok(_) => None,
                };
                // A service proof has AAL 0 and cannot satisfy any human
                // assurance rule. Evaluate after the remote exchange against
                // the current application snapshot, over HTTP and HOP1 alike.
                if let Some(reason) = refused {
                    let decision = Decision::Deny {
                        reason,
                        kind: DenyKind::Forbidden,
                    };
                    st.count_decision(&decision);
                    st.denied(
                        &decision,
                        None,
                        Some(input.client_ip),
                        None,
                        None,
                        &request_id,
                    );
                    return hangang::render(decision, input.navigation, &env, &st.cfg);
                }
            }
            return hangang::service_identity::response(evidence.as_ref(), &request_id);
        }
    }
    let document = matches!(input.navigation, Navigation::Document);
    let client_ip = input.client_ip;

    let ctx = st.ctx.with_budget();
    let (decision, cause) = match tokio::time::timeout(
        ctx.limits.budget,
        crate::verify::decide_with_cause(&ctx, input),
    )
    .await
    {
        Ok(d) => d,
        Err(_) => (
            Decision::Deny {
                reason: reasons::BUDGET_EXCEEDED,
                kind: DenyKind::Unavailable {
                    retry_after: Duration::from_secs(1),
                },
            },
            None,
        ),
    };
    st.count_decision(&decision);
    st.denied(&decision, cause, Some(client_ip), None, None, &request_id);
    let nav = if document {
        Navigation::Document
    } else {
        Navigation::Other
    };
    hangang::render(decision, nav, &env, &st.cfg)
}
