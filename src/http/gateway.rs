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
    capture_service_receipts: bool,
    human_owner: Option<Arc<crate::verify::human::Owner>>,
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
            capture_service_receipts: false,
            human_owner: None,
            authentication_gateway: None,
        })
    }

    pub(crate) fn with_human_owner(
        mut self: Arc<Self>,
        owner: Arc<crate::verify::human::Owner>,
    ) -> anyhow::Result<Arc<Self>> {
        let state = Arc::get_mut(&mut self)
            .ok_or_else(|| anyhow::anyhow!("gateway state already shared"))?;
        if !owner.matches(&state.ctx) {
            anyhow::bail!("native Human context mismatch");
        }
        state.human_owner = Some(owner);
        Ok(self)
    }

    pub fn with_authentication_gateway(
        mut self: Arc<Self>,
        runtime: crate::auth_gateway::runtime::Runtime,
    ) -> anyhow::Result<Arc<Self>> {
        Arc::get_mut(&mut self)
            .ok_or_else(|| anyhow::anyhow!("authentication gateway state is already shared"))?
            .authentication_gateway = Some(Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::auth_gateway::authority::Snapshot {
                publication: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                revision: 0,
                runtime: Some(runtime),
            },
        )));
        Ok(self)
    }

    pub fn with_service_receipt_capture(mut self: Arc<Self>) -> anyhow::Result<Arc<Self>> {
        Arc::get_mut(&mut self)
            .ok_or_else(|| anyhow::anyhow!("gateway state is already shared"))?
            .capture_service_receipts = true;
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

async fn verify(
    State(st): State<Arc<GatewayState>>,
    workload: Option<axum::extract::Extension<Arc<crate::auth_gateway::workload_owner::Attempt>>>,
    human: Option<axum::extract::Extension<crate::verify::human::Capture>>,
    headers: HeaderMap,
) -> Response {
    if human.is_some() && workload.is_some() {
        return hangang::service_identity::unavailable("native-human");
    }
    // Private adapter extension only; no client header selects this path.
    let human_admission = if let Some(axum::extract::Extension(capture)) = human {
        match st.human_owner.as_ref().and_then(|owner| {
            capture
                .take(owner)
                .ok()
                .map(|admission| (owner.clone(), admission))
        }) {
            Some(admission) => Some(admission),
            None => return hangang::service_identity::unavailable("native-human"),
        }
    } else {
        None
    };
    let workload = workload.map(|axum::extract::Extension(attempt)| attempt);
    let workload_application = workload.as_ref().map(|_| st.ctx.snapshot.load_full());
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
    if human_admission.is_some()
        && (workload.is_some() || headers.contains_key(axum::http::header::AUTHORIZATION))
    {
        return hangang::service_identity::unavailable(&request_id);
    }
    let authority = st
        .authentication_gateway
        .as_ref()
        .map(|reader| reader.load_full());
    if authority
        .as_ref()
        .is_some_and(|snapshot| !snapshot.available())
        && matches!(
            input.canonical_path.reserved(),
            crate::verify::types::Reserved::No
        )
    {
        return hangang::service_identity::unavailable(&request_id);
    }
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
        let presented = hangang::service_identity::credential(&headers);
        let fallback = matches!(presented, Ok(None))
            && runtime.session_fallback(input.host.as_str(), input.port);
        if !fallback {
            if human_admission.is_some() {
                return hangang::service_identity::unavailable(&request_id);
            }
            if let Some(attempt) = &workload
                && attempt.now(st.ctx.clock.as_ref()).is_err()
            {
                return hangang::service_identity::unavailable(&request_id);
            }
            // Keep the paired native clock capability through final HTTP output,
            // including non-receipt callers and callbacks after provider return.
            let entry_stamp = if matches!(
                presented,
                Ok(Some(
                    crate::auth_gateway::composition::Credential::Composite(_)
                ))
            ) {
                match crate::auth_gateway::composition::EntryTime::capture(st.ctx.clock.as_ref()) {
                    Ok(time) => Some(time),
                    Err(_) => return hangang::service_identity::unavailable(&request_id),
                }
            } else {
                None
            };
            let result = match presented {
                Ok(token) => tokio::time::timeout(st.ctx.limits.budget, async {
                    let now = entry_stamp.as_ref().map_or_else(
                        || st.ctx.clock.now().0.max(0) as u64,
                        |time| time.entry_ms(),
                    );
                    if st.capture_service_receipts {
                        let captured = authority
                            .as_ref()
                            .ok_or(crate::auth_gateway::runtime::Error::Unavailable)?;
                        let proof = captured
                            .authenticate_credential_for_receipt(
                                input.host.as_str(),
                                input.port,
                                token,
                                input.client_ip,
                                now,
                                entry_stamp.as_ref(),
                            )
                            .await?;
                        Ok((proof.evidence.clone(), Some(proof)))
                    } else {
                        runtime
                            .authenticate_credential_async(
                                input.host.as_str(),
                                input.port,
                                token,
                                input.client_ip,
                                now,
                                entry_stamp.as_ref(),
                            )
                            .await
                            .map(|evidence| (evidence, None))
                    }
                })
                .await
                .unwrap_or(Err(crate::auth_gateway::runtime::Error::Unavailable)),
                Err(_) => Err(crate::auth_gateway::runtime::Error::Invalid),
            };
            let current = st
                .authentication_gateway
                .as_ref()
                .map(|reader| reader.load_full());
            let result =
                if current
                    .as_ref()
                    .zip(authority.as_ref())
                    .is_some_and(|(current, captured)| {
                        current.available() && Arc::ptr_eq(current, captured)
                    })
                {
                    result
                } else {
                    Err(crate::auth_gateway::runtime::Error::Unavailable)
                };
            let unavailable = matches!(
                result,
                Err(crate::auth_gateway::runtime::Error::Unavailable)
            );
            let (evidence, receipt_proof) = result
                .ok()
                .map_or((None, None), |(evidence, proof)| (Some(evidence), proof));
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
            let mut validated_application = None;
            if evidence.is_some() {
                let policy = st.ctx.snapshot.load_full();
                if let Some(captured) = &workload_application
                    && !Arc::ptr_eq(captured, &policy)
                {
                    if let Some(attempt) = &workload {
                        attempt.retire();
                    }
                    return hangang::service_identity::unavailable(&request_id);
                }
                if st.capture_service_receipts || entry_stamp.is_some() {
                    validated_application = Some(policy.clone());
                }
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
                // Service and workload proofs have AAL 0 and cannot satisfy human
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
            let mut response = hangang::service_identity::response_at(
                evidence.as_ref(),
                &request_id,
                st.ctx.clock.now().0.max(0) as u64,
            );
            if response.status().is_success()
                && let (Some(proof), Some(profile), Some(application)) = (
                    receipt_proof,
                    authority.as_ref(),
                    validated_application.clone(),
                )
            {
                if let Some(attempt) = &workload {
                    match crate::auth_gateway::receipt_issuer::CapturedWorkload::new(
                        proof,
                        profile.clone(),
                        application,
                        attempt.clone(),
                    ) {
                        Ok(captured) => {
                            response.extensions_mut().insert(Arc::new(captured));
                        }
                        Err(_) => return hangang::service_identity::unavailable(&request_id),
                    }
                } else {
                    response.extensions_mut().insert(Arc::new(
                        crate::auth_gateway::receipt_issuer::CapturedService {
                            authentication: proof,
                            profile: profile.clone(),
                            application,
                        },
                    ));
                }
            }
            if response.status().is_success()
                && let (Some(time), Some(evidence)) = (entry_stamp.as_ref(), evidence.as_ref())
            {
                let now = match time.current(&runtime.observed_time, evidence.expires_at_ms()) {
                    Ok(now) => now,
                    Err(_) => return hangang::service_identity::unavailable(&request_id),
                };
                // Time dependencies may overlap publication; owner fences follow
                // the final native clock callback, not merely provider completion.
                let current = st
                    .authentication_gateway
                    .as_ref()
                    .map(|reader| reader.load_full());
                if !current
                    .as_ref()
                    .zip(authority.as_ref())
                    .is_some_and(|(current, captured)| {
                        current.available() && Arc::ptr_eq(current, captured)
                    })
                    || !validated_application
                        .as_ref()
                        .is_some_and(|captured| Arc::ptr_eq(captured, &st.ctx.snapshot.load_full()))
                {
                    return hangang::service_identity::unavailable(&request_id);
                }
                let remaining = evidence.expires_at_ms() - now;
                response.headers_mut().insert(
                    "x-hopae-evidence-ttl-ms",
                    axum::http::HeaderValue::from_str(&remaining.min(1000).to_string())
                        .expect("bounded remaining duration"),
                );
            }
            return response;
        }
    }
    let document = matches!(input.navigation, Navigation::Document);
    let client_ip = input.client_ip;

    let ctx = st.ctx.with_budget();
    let (decision, cause, witness) = if let Some((owner, admission)) = human_admission {
        crate::verify::decide_for_human(&ctx, &input, owner, admission).await
    } else {
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
        return hangang::render(
            decision,
            if document {
                Navigation::Document
            } else {
                Navigation::Other
            },
            &env,
            &st.cfg,
        );
    };
    st.count_decision(&decision);
    st.denied(&decision, cause, Some(client_ip), None, None, &request_id);
    let nav = if document {
        Navigation::Document
    } else {
        Navigation::Other
    };
    let mut response = hangang::render(decision, nav, &env, &st.cfg);
    if let Some(witness) = witness {
        match witness.finish(&input).await {
            Ok(checked) => {
                response.extensions_mut().insert(Arc::new(checked));
            }
            Err(_) => return hangang::service_identity::unavailable(&request_id),
        }
    }
    response
}
