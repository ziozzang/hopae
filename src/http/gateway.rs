//! The gateway listener: `GET /_hopae/verify`. Wire details live in
//! `crate::gateway::hangang`; this module owns the concurrency limit, the
//! verify budget and the call into the core.

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

use crate::event::types::reasons;
use crate::gateway::hangang::{self, GatewayConfig, RenderEnv};
use crate::verify::types::{CallerAuth, Decision, DenyKind, KeySlot, Navigation, VerifyContext};

/// Increment a named counter with labels. The default does nothing; the
/// process wiring installs `telemetry::counters::inc`.
pub type CounterFn = Arc<dyn Fn(&str, &[(&str, &str)]) + Send + Sync>;

/// Shared state of the gateway listener.
pub struct GatewayState {
    pub cfg: GatewayConfig,
    pub ctx: VerifyContext,
    limit: Arc<Semaphore>,
    counters: CounterFn,
    next_id: AtomicU64,
    id_salt: RandomState,
}

impl GatewayState {
    /// `max_concurrent` is `limits.gateway_max_concurrent`.
    pub fn new(
        cfg: GatewayConfig,
        ctx: VerifyContext,
        max_concurrent: u32,
        counters: Option<CounterFn>,
    ) -> Arc<Self> {
        Arc::new(GatewayState {
            cfg,
            ctx,
            limit: Arc::new(Semaphore::new(max_concurrent as usize)),
            counters: counters.unwrap_or_else(|| Arc::new(|_, _| {})),
            next_id: AtomicU64::new(0),
            id_salt: RandomState::new(),
        })
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
            "hopae_verify_decisions_total",
            &[("decision", name), ("reason", reason)],
        );
        if matches!(decision, Decision::Deny { reason: r, .. } if *r == reasons::STORE_UNAVAILABLE)
        {
            self.count("hopae_store_errors_total", &[]);
        }
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
    let Ok(_permit) = st.limit.clone().try_acquire_owned() else {
        st.count("hopae_verify_overloaded_total", &[]);
        let decision = Decision::Deny {
            reason: reasons::OVERLOADED,
            kind: DenyKind::Unavailable {
                retry_after: Duration::from_secs(1),
            },
        };
        st.count_decision(&decision);
        let env = RenderEnv {
            request_id,
            ..RenderEnv::default()
        };
        return hangang::render(decision, Navigation::Other, &env, &st.cfg);
    };

    let parsed = match hangang::parse(&st.cfg, &headers, request_id) {
        Ok(p) => p,
        Err(rej) => {
            if let Some(metric) = rej.metric {
                st.count(metric, &[]);
            }
            st.count_decision(&rej.decision);
            return hangang::render(rej.decision, Navigation::Other, &rej.env, &st.cfg);
        }
    };
    let (input, env) = (parsed.input, parsed.env);
    if let CallerAuth::Keyed { which } = &input.caller {
        let key = match which {
            KeySlot::Current => "current",
            KeySlot::Next => "next",
        };
        st.count("hopae_verify_caller_key_total", &[("key", key)]);
    }
    let document = matches!(input.navigation, Navigation::Document);

    let ctx = st.ctx.with_budget();
    let decision =
        match tokio::time::timeout(ctx.limits.budget, crate::verify::decide(&ctx, input)).await {
            Ok(d) => d,
            Err(_) => Decision::Deny {
                reason: reasons::BUDGET_EXCEEDED,
                kind: DenyKind::Unavailable {
                    retry_after: Duration::from_secs(1),
                },
            },
        };
    st.count_decision(&decision);
    let nav = if document {
        Navigation::Document
    } else {
        Navigation::Other
    };
    hangang::render(decision, nav, &env, &st.cfg)
}
