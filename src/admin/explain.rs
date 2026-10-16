//! `POST /v1/explain/authentication` (ADR-0019 explain/simulate, ADR-0020):
//! what the gateway's authentication check would answer for a target URL
//! and a subject — which application policy or service profile applies,
//! which providers and factors are available, the assurance level, the
//! step-up rule and the freshness bound — and why, as stable reason codes.
//!
//! The evaluation calls the functions the live verify and service paths
//! call (`apps::validate_return_target`, `apps::resolve`, the reserved
//! namespace, `lifetimes::evaluate`, `binding::check`, `step_up::evaluate`,
//! `freshness::console_fresh`, the service runtime's network predicate and
//! eligibility script), in the live order. It reads the stores and never
//! writes: no session, handle, transaction or touch is created, and a
//! session the simulation finds expired is not terminated.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::explain_messages;
use super::reads::{self, Op, Privacy};
use super::subjects::{self, Ref, Sources};
use super::users::common::{Fail, store_failure};
use super::{AdminState, Ctx, api};
use crate::auth_gateway::runtime::KeyVerdict;
use crate::crypto::{Digest, Timestamp};
use crate::event::types::reasons;
use crate::identity::types::UserId;
use crate::policy::binding::{self, BindingVerdict};
use crate::policy::types::{AppPolicy, AuthzChange, ConfigSnapshot, Host, IpBinding, OnMismatch};
use crate::policy::{apps, freshness, step_up};
use crate::portal::i18n::Lang;
use crate::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use crate::store::types::{AuthTimeSource, HandleRow, IdentitySnapshot, SessionRow, UserStatus};
use crate::verify::lifetimes::{self, LifetimeVerdict};
use crate::verify::types::{CanonicalPath, Reserved};

/// Furthest a simulated time may lie from now.
pub const MAX_TIME_SHIFT: Duration = Duration::from_secs(30 * 86_400);

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Hypothetical {
    #[serde(default)]
    aal: Option<i64>,
    #[serde(default)]
    factors: Option<Vec<String>>,
    #[serde(default)]
    auth_age_seconds: Option<u64>,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    auth_time_source: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    url: String,
    #[serde(default)]
    navigation: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    client_ip: Option<IpAddr>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    at: Option<i64>,
    #[serde(default)]
    hypothetical: Option<Hypothetical>,
    #[serde(default)]
    privacy_profile: Privacy,
}

/// The answer a simulated request would get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Login,
    StepUp,
    Reauth,
    Deny,
    Unavailable,
    Indeterminate,
    NotApplicable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Login => "login",
            Outcome::StepUp => "step_up",
            Outcome::Reauth => "reauth",
            Outcome::Deny => "deny",
            Outcome::Unavailable => "unavailable",
            Outcome::Indeterminate => "indeterminate",
            Outcome::NotApplicable => "not_applicable",
        }
    }
}

/// A verdict with its stable reason (short code, see the catalogue).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub outcome: Outcome,
    pub code: &'static str,
}

/// Refusals of the service path: the gateway answers them as the service
/// identity `401` (with `www-authenticate`), not as a `403`.
const SERVICE_REFUSALS: &[&str] = &[
    "service_credential_required",
    "service_profile_absent",
    "service_principal_unknown",
    "credential_expired",
    "network_denied",
    "eligibility_denied",
    "workload_subject_invalid",
    "workload_namespace_not_allowed",
    "workload_service_account_not_allowed",
    "workload_service_account_absent",
];

impl Verdict {
    /// The status the gateway's answer carries for a document navigation
    /// (`document`) or another request.
    pub fn status(self, document: bool) -> Option<u16> {
        Some(match self.outcome {
            Outcome::Allow => 200,
            Outcome::Login | Outcome::Reauth if document => 302,
            Outcome::Login | Outcome::Reauth => 401,
            Outcome::StepUp => 302,
            Outcome::Deny if SERVICE_REFUSALS.contains(&self.code) => 401,
            Outcome::Deny => 403,
            Outcome::Unavailable => 503,
            Outcome::Indeterminate | Outcome::NotApplicable => return None,
        })
    }
}

fn v(outcome: Outcome, code: &'static str) -> Verdict {
    Verdict { outcome, code }
}

/// The ordered record of the checks made.
struct Trace {
    lang: Lang,
    steps: Vec<Value>,
}

impl Trace {
    fn reason(&self, code: &str) -> Value {
        json!({
            "code": format!("hopae.{code}"),
            "message_key": format!("hopae.explain.{code}"),
            "message": explain_messages::message(code, self.lang),
        })
    }

    fn step(
        &mut self,
        check: &'static str,
        result: &'static str,
        code: Option<&str>,
        detail: Value,
    ) {
        let mut step = json!({ "check": check, "result": result, "detail": detail });
        if let Some(code) = code {
            step["reason"] = self.reason(code);
        }
        self.steps.push(step);
    }
}

fn aal_num(a: Aal) -> i64 {
    a.as_i64()
}

fn secs(d: Duration) -> u64 {
    d.as_secs()
}

fn app_json(app: &AppPolicy, snapshot: &ConfigSnapshot) -> Value {
    let ip = match app.binding.ip {
        IpBinding::Strict => json!("strict"),
        IpBinding::Prefix { v4, v6 } => json!({"prefix": {"v4": v4, "v6": v6}}),
        IpBinding::Off => json!("off"),
    };
    json!({
        "app_id": app.app_id.as_str(),
        "display_name": app.display_name,
        "enabled": app.enabled,
        "session": {"idle_seconds": secs(app.session.idle), "absolute_seconds": secs(app.session.absolute)},
        "binding": {
            "ip": ip,
            "ua": matches!(app.binding.ua, crate::policy::types::UaBinding::Strict),
            "on_mismatch": match app.binding.on_mismatch {
                OnMismatch::TerminateSession => "terminate_session",
                OnMismatch::DropHandle => "drop_handle",
            },
        },
        "on_authz_change": match app.on_authz_change {
            AuthzChange::Refresh => "refresh",
            AuthzChange::Terminate => "terminate",
        },
        "verify_cache_seconds": app.verify_cache_seconds,
        "max_auth_age_seconds": app.max_auth_age.map(secs),
        "step_up_rules": app.step_up.iter().map(|r| json!({
            "path_prefix": r.path_prefix,
            "aal": aal_num(r.aal),
            "max_age_seconds": r.max_age.map(secs),
        })).collect::<Vec<_>>(),
        "config_generation": snapshot.generation,
    })
}

/// The step-up evaluation of the live path, plus which rule decided it.
fn step_up_of(
    app: &AppPolicy,
    path: &str,
    session: &SessionRow,
    handle_aal: Aal,
    now: Timestamp,
) -> (step_up::StepUpVerdict, Value) {
    let verdict = step_up::evaluate(
        &app.step_up,
        path,
        handle_aal,
        session.auth_time,
        &session.factors,
        now,
    );
    let matched: Vec<usize> = app
        .step_up
        .iter()
        .enumerate()
        .filter(|(_, r)| step_up::rule_matches(r, path))
        .map(|(i, _)| i)
        .collect();
    // The live evaluation stops at the first matching rule that is not
    // satisfied; evaluating rules one at a time names it.
    let deciding = matched.iter().copied().find(|&i| {
        step_up::evaluate(
            std::slice::from_ref(&app.step_up[i]),
            path,
            handle_aal,
            session.auth_time,
            &session.factors,
            now,
        ) != step_up::StepUpVerdict::NotRequired
    });
    let required = app
        .step_up
        .iter()
        .filter(|r| step_up::rule_matches(r, path))
        .map(|r| aal_num(r.aal))
        .max()
        .unwrap_or(1);
    (
        verdict,
        json!({
            "matched_rules": matched,
            "deciding_rule": deciding,
            "required_aal": required,
            "verdict": match verdict {
                step_up::StepUpVerdict::NotRequired => json!("not_required"),
                step_up::StepUpVerdict::Required { aal, max_age } => json!({
                    "required": {"aal": aal_num(aal), "max_age_seconds": max_age.map(secs)},
                }),
            },
        }),
    )
}

/// After the session checks: step-up rules, then the freshness bound —
/// the order and decisions of the live flow.
fn post_auth(
    t: &mut Trace,
    env: &Env<'_>,
    app: &AppPolicy,
    session: &SessionRow,
    handle_aal: Aal,
) -> (Verdict, Value, Value) {
    let (verdict, detail) = step_up_of(app, env.path.as_str(), session, handle_aal, env.now);
    let mut freshness_json = Value::Null;
    if let step_up::StepUpVerdict::Required { aal, .. } = verdict {
        t.step("step_up", "fail", Some("step_up_required"), detail.clone());
        let out = if env.document && aal == Aal::One {
            if session.auth_time > env.now {
                v(Outcome::Unavailable, "clock_skew")
            } else {
                v(Outcome::Reauth, "reauth_required")
            }
        } else if env.document && env.limits.stepup_enabled {
            v(Outcome::StepUp, "step_up_required")
        } else if env.document {
            v(Outcome::Deny, "step_up_unavailable")
        } else {
            v(Outcome::Login, "step_up_required")
        };
        return (out, detail, freshness_json);
    }
    t.step("step_up", "pass", None, detail.clone());
    if let Some(n) = app.max_auth_age {
        let capability = env.snapshot.reauth_capability(&session.provider_id);
        let fresh = freshness::console_fresh(session, capability, env.now, n);
        freshness_json = json!({
            "max_auth_age_seconds": secs(n),
            "auth_age_seconds": env.now.secs().saturating_sub(session.auth_time.secs()),
            "auth_time_source": session.auth_time_source.as_str(),
            "provider_capability": capability.as_str(),
            "fresh": fresh,
        });
        if !fresh {
            t.step(
                "freshness",
                "fail",
                Some("reauth_required"),
                freshness_json.clone(),
            );
            return (
                v(Outcome::Reauth, "reauth_required"),
                detail,
                freshness_json,
            );
        }
        t.step("freshness", "pass", None, freshness_json.clone());
    }
    (v(Outcome::Allow, "allowed"), detail, freshness_json)
}

/// What one evaluation reads, gathered once.
struct Env<'a> {
    st: &'a AdminState,
    snapshot: Arc<ConfigSnapshot>,
    limits: crate::verify::types::VerifyLimits,
    url: url::Url,
    host: Host,
    port: u16,
    path: CanonicalPath,
    document: bool,
    client_ip: Option<IpAddr>,
    user_agent: Option<String>,
    now: Timestamp,
}

/// The person a simulation is about.
struct Person {
    user_id: String,
    user: Option<crate::store::types::User>,
    providers: Vec<String>,
}

fn factor_kind(name: &str) -> Option<FactorKind> {
    serde_json::from_value(json!(name)).ok()
}

/// A session as a fresh sign-in would create it now (or as the hypothesis says).
fn hypothetical_session(
    env: &Env<'_>,
    person: Option<&Person>,
    h: &Hypothetical,
) -> Result<(SessionRow, HandleRow), Fail> {
    let aal = match h.aal {
        None => Aal::One,
        Some(n) => Aal::from_i64(n).ok_or_else(reads::invalid)?,
    };
    let auth_time = Timestamp::from_secs(env.now.secs().saturating_sub(
        i64::try_from(h.auth_age_seconds.unwrap_or(0)).map_err(|_| reads::invalid())?,
    ));
    let mut factors = Vec::new();
    for name in h.factors.iter().flatten().take(8) {
        factors.push(FactorEntry {
            kind: factor_kind(name).ok_or_else(reads::invalid)?,
            provider: None,
            at: auth_time,
        });
    }
    let source = match h.auth_time_source.as_deref() {
        None | Some("hopae_completion") => AuthTimeSource::HopaeCompletion,
        Some("provider_claim") => AuthTimeSource::ProviderClaim,
        Some(_) => return Err(reads::invalid()),
    };
    let provider = h
        .provider_id
        .clone()
        .or_else(|| person.and_then(|p| p.providers.first().cloned()))
        .or_else(|| {
            env.snapshot
                .providers
                .iter()
                .filter(|p| p.enabled)
                .min_by_key(|p| p.sort_order)
                .map(|p| p.provider_id.to_string())
        })
        .unwrap_or_default();
    let user = person.map_or_else(|| "u_hypothetical".to_string(), |p| p.user_id.clone());
    let authz = person
        .and_then(|p| p.user.as_ref())
        .map_or(1, |u| u.authz_version);
    let session = SessionRow {
        session_id: SessionId::new("s_hypothetical"),
        user_id: UserId::new(user),
        provider_id: crate::provider::types::ProviderId::new(provider),
        auth_time,
        factors,
        aal,
        authz_version: authz,
        cred_gen: 1,
        snapshot: IdentitySnapshot {
            email: None,
            display_name: None,
            username: None,
            groups: Vec::new(),
        },
        bound_ip: env
            .client_ip
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        bound_ua_sha256: None,
        created_at: env.now,
        last_seen_at: env.now,
        absolute_expires_at: env.now.add(env.limits.session.absolute),
        terminated_at: None,
        terminated_reason: None,
        authz_version_at_auth: authz,
        auth_time_source: source,
        bound_ua_prefix: None,
    };
    let handle = HandleRow {
        handle_sha256: Digest([0; 32]),
        session_id: session.session_id.clone(),
        host: env.host.clone(),
        issued_aal: aal,
        created_at: env.now,
        last_seen_at: env.now,
        absolute_expires_at: env.now.add(Duration::from_secs(7 * 86_400)),
        revoked_at: None,
        revoked_reason: None,
    };
    Ok((session, handle))
}

fn session_json(s: &SessionRow, h: Option<&HandleRow>, hypothetical: bool) -> Value {
    json!({
        "session_id": (!hypothetical).then(|| s.session_id.to_string()),
        "hypothetical": hypothetical,
        "provider_id": s.provider_id.as_str(),
        "aal": aal_num(s.aal),
        "handle_aal": h.map(|h| aal_num(h.issued_aal)),
        "factors": s.factors.iter().map(|f| json!({"kind": f.kind.as_str(), "at": f.at.secs()})).collect::<Vec<_>>(),
        "auth_time": s.auth_time.secs(),
        "auth_time_source": s.auth_time_source.as_str(),
        "created_at": s.created_at.secs(),
        "last_seen_at": s.last_seen_at.secs(),
        "terminated": s.terminated_at.is_some(),
    })
}

fn fetch(c: &Ctx) -> impl Fn(crate::store::StoreError) -> Fail + '_ {
    move |e| store_failure(c, "explain", &e)
}

/// The live session's checks (`authenticate` in the engine), read-only.
async fn evaluate_session(
    t: &mut Trace,
    env: &Env<'_>,
    c: &Ctx,
    app: &AppPolicy,
    session: &SessionRow,
) -> Result<(Verdict, Option<HandleRow>, Value, Value), Fail> {
    let st = env.st;
    let handle = st
        .profile_store
        .admin_live_handle(
            session.session_id.to_string(),
            env.host.as_str().to_string(),
            api::deadline(st),
        )
        .await
        .map_err(fetch(c))?;
    if session.terminated_at.is_some() {
        t.step("session", "fail", Some("session_terminated"), json!({}));
        return Ok((
            v(Outcome::Login, "session_terminated"),
            handle,
            Value::Null,
            Value::Null,
        ));
    }
    let Some(handle) = handle else {
        t.step(
            "handle",
            "fail",
            Some("handle_absent"),
            json!({"host": env.host.as_str()}),
        );
        return Ok((
            v(Outcome::Login, "handle_absent"),
            None,
            Value::Null,
            Value::Null,
        ));
    };
    match lifetimes::evaluate(&handle, session, &app.session, &env.limits.session, env.now) {
        LifetimeVerdict::Live { expires_at } => {
            t.step(
                "lifetimes",
                "pass",
                None,
                json!({"expires_at": expires_at.secs()}),
            );
        }
        LifetimeVerdict::ClockSkew => {
            t.step("lifetimes", "fail", Some("clock_skew"), json!({}));
            return Ok((
                v(Outcome::Unavailable, "clock_skew"),
                Some(handle),
                Value::Null,
                Value::Null,
            ));
        }
        LifetimeVerdict::HandleExpired(r) | LifetimeVerdict::SessionExpired(r) => {
            let code = if r == reasons::IDLE {
                "idle"
            } else {
                "absolute"
            };
            t.step("lifetimes", "fail", Some(code), json!({}));
            return Ok((
                v(Outcome::Login, code),
                Some(handle),
                Value::Null,
                Value::Null,
            ));
        }
    }
    match env.client_ip {
        None => t.step("binding", "skip", Some("binding_not_evaluated"), json!({})),
        Some(ip) => match binding::check(
            &app.binding,
            session.bound_ip,
            session.bound_ua_sha256.as_ref(),
            ip,
            env.user_agent.as_deref(),
        ) {
            BindingVerdict::Ok => t.step("binding", "pass", None, json!({})),
            BindingVerdict::Mismatch { signal, .. } => {
                let code = if signal == binding::BindSignal::Ip {
                    "binding_ip"
                } else {
                    "binding_ua"
                };
                t.step(
                    "binding",
                    "fail",
                    Some(code),
                    json!({"signal": signal.as_str()}),
                );
                return Ok((
                    v(Outcome::Login, code),
                    Some(handle),
                    Value::Null,
                    Value::Null,
                ));
            }
        },
    }
    let authz = st
        .directory
        .user_authz(&session.user_id)
        .await
        .map_err(fetch(c))?;
    match authz {
        None => {
            t.step(
                "user",
                "fail",
                Some("user_disabled"),
                json!({"present": false}),
            );
            return Ok((
                v(Outcome::Login, "user_disabled"),
                Some(handle),
                Value::Null,
                Value::Null,
            ));
        }
        Some(u) if u.status == UserStatus::Disabled => {
            t.step("user", "fail", Some("user_disabled"), json!({}));
            return Ok((
                v(Outcome::Login, "user_disabled"),
                Some(handle),
                Value::Null,
                Value::Null,
            ));
        }
        Some(u)
            if app.on_authz_change == AuthzChange::Terminate
                && u.authz_version != session.authz_version_at_auth =>
        {
            t.step("user", "fail", Some("authz_change"), json!({}));
            return Ok((
                v(Outcome::Login, "authz_change"),
                Some(handle),
                Value::Null,
                Value::Null,
            ));
        }
        Some(_) => t.step("user", "pass", None, json!({})),
    }
    let handle_aal = handle.issued_aal.min(session.aal);
    let (verdict, step, fresh) = post_auth(t, env, app, session, handle_aal);
    Ok((verdict, Some(handle), step, fresh))
}

fn assurance_json(
    current: Option<i64>,
    required: i64,
    achievable: i64,
    totp_configured: bool,
    totp_enrolled: Option<bool>,
    external: &[String],
) -> Value {
    json!({
        "current_aal": current,
        "required_aal": required,
        "achievable_aal": achievable,
        "second_factors": {
            "totp_configured": totp_configured,
            "totp_enrolled": totp_enrolled,
            "external": external,
        },
    })
}

#[allow(clippy::too_many_lines)]
async fn explain(st: &AdminState, c: &Ctx, req: Request) -> Result<Value, Fail> {
    let mut t = Trace {
        lang: c.req.lang,
        steps: Vec::new(),
    };
    let real_now = st.clock.now();
    let now = match req.at {
        None => real_now,
        Some(at) => {
            let shift = i64::try_from(MAX_TIME_SHIFT.as_secs()).unwrap_or(i64::MAX);
            if (at - real_now.secs()).abs() > shift {
                return Err(reads::invalid());
            }
            Timestamp::from_secs(at)
        }
    };
    let document = match req.navigation.as_deref() {
        None | Some("document") => true,
        Some("other") => false,
        Some(_) => return Err(reads::invalid()),
    };
    if req.session_id.is_some() && req.subject.is_some() {
        return Err(reads::invalid());
    }
    if req.url.len() > apps::MAX_URL_BYTES || req.user_agent.as_ref().is_some_and(|u| u.len() > 512)
    {
        return Err(reads::invalid());
    }
    let url = url::Url::parse(&req.url).map_err(|_| reads::invalid())?;
    let host = Host::parse(url.host_str().unwrap_or_default()).map_err(|_| reads::invalid())?;
    let port = url.port_or_known_default().ok_or_else(reads::invalid)?;
    let snapshot = st.snapshot.load_full();
    let limits = st.verify.limits;
    let src = Sources::of(st).await.map_err(fetch(c))?;
    let user_agent = req
        .user_agent
        .as_deref()
        .map(|u| crate::policy::binding::normalize_user_agent(u.as_bytes()));
    let hypothetical = req.hypothetical.unwrap_or_default();
    let totp_configured = st.profile_config.totp_keyring.is_some();
    let external: Vec<String> = st
        .profile_config
        .external_verifiers
        .iter()
        .map(|e| e.factor.clone())
        .collect();
    let achievable = if limits.stepup_enabled && (totp_configured || !external.is_empty()) {
        2
    } else {
        1
    };
    let service_snapshot = reads::service_snapshot(st);
    let profile_revision = service_snapshot.as_ref().map(|s| s.revision);

    // The subject: a live session, a person, a service principal or nobody.
    let subject_ref = req.subject.clone();
    let mut subject_item = Value::Null;
    let mut person: Option<Person> = None;
    let mut session: Option<SessionRow> = None;
    let mut service_principal = false;
    // A Kubernetes workload named by SPIFFE ID or `system:serviceaccount:`.
    let mut workload_principal = false;
    if let Some(id) = &req.session_id {
        if !super::users::common::valid_session_id(id) {
            return Err(reads::invalid());
        }
        session = st
            .sessions
            .session(&SessionId::new(id.clone()))
            .await
            .map_err(fetch(c))?;
        if let Some(s) = &session {
            let (items, _) = subjects::resolve(&src, &[s.user_id.to_string()], req.privacy_profile)
                .await
                .map_err(fetch(c))?;
            subject_item = serde_json::to_value(&items[0]).unwrap_or(Value::Null);
        }
    } else if let Some(id) = &subject_ref {
        if id.is_empty() || id.len() > subjects::MAX_REF_BYTES {
            return Err(reads::invalid());
        }
        let (items, _) = subjects::resolve(&src, std::slice::from_ref(id), req.privacy_profile)
            .await
            .map_err(fetch(c))?;
        subject_item = serde_json::to_value(&items[0]).unwrap_or(Value::Null);
        service_principal = subjects::classify(id) == Ref::Service;
        workload_principal = crate::auth_gateway::runtime::is_workload_subject(id);
        service_principal |= workload_principal;
    }
    let person_id = session
        .as_ref()
        .map(|s| s.user_id.to_string())
        .or_else(|| subject_item["user_id"].as_str().map(str::to_string));
    if let Some(user_id) = person_id {
        let rows = st
            .profile_store
            .admin_directory_rows(vec![user_id.clone()], api::deadline(st))
            .await
            .map_err(fetch(c))?;
        let row = rows.get(&user_id);
        person = Some(Person {
            user: row.and_then(|r| r.user.clone()),
            providers: row.map(|r| r.providers.clone()).unwrap_or_default(),
            user_id,
        });
    }
    let totp_enrolled = match &person {
        Some(p) => Some(
            st.profile_store
                .admin_totp_active(p.user_id.clone(), api::deadline(st))
                .await
                .map_err(fetch(c))?,
        ),
        None => None,
    };
    let providers: Vec<Value> = {
        let mut list: Vec<_> = snapshot.providers.iter().collect();
        list.sort_by_key(|p| p.sort_order);
        list.iter()
            .map(|p| {
                json!({
                    "provider_id": p.provider_id.as_str(),
                    "kind": p.kind.as_str(),
                    "display_name": p.display_name,
                    "enabled": p.enabled,
                    "reauth": p.reauth.as_str(),
                    "linked": person.as_ref().map(|person| person.providers.iter().any(|x| x == p.provider_id.as_str())),
                })
            })
            .collect()
    };

    let mut env = Env {
        st,
        snapshot: snapshot.clone(),
        limits,
        url: url.clone(),
        host: host.clone(),
        port,
        path: CanonicalPath::new(String::new()),
        document,
        client_ip: req.client_ip,
        user_agent,
        now,
    };
    let mut application = Value::Null;
    let mut service_profile = Value::Null;
    let mut session_out = Value::Null;
    let mut step_up_out = Value::Null;
    let mut fresh_out = Value::Null;
    let mut after_login = Value::Null;
    let mut current_aal: Option<i64> = None;
    let mut required_aal = 1;

    let verdict: Verdict = 'decide: {
        // The adapter's canonical path, then the core's own contract checks.
        let Ok(path) = crate::gateway::canonical::canonical_path(url.path()) else {
            t.step("path", "fail", Some("path_not_canonical"), json!({}));
            break 'decide v(Outcome::Deny, "path_not_canonical");
        };
        env.path = path;
        t.step(
            "path",
            "pass",
            None,
            json!({"canonical_path": env.path.as_str()}),
        );

        // The gateway's service authentication step, before the verify
        // engine: publication in progress, a credential on a host without a
        // profile, then the profile's own path (AAL 0) unless it falls back
        // to browser sessions. Reserved paths always go to the engine.
        if let Some(snap) = &service_snapshot
            && env.path.reserved() == Reserved::No
        {
            if !snap.available() {
                t.step(
                    "service_profile",
                    "fail",
                    Some("authority_unavailable"),
                    json!({}),
                );
                break 'decide v(Outcome::Unavailable, "authority_unavailable");
            }
            let runtime = snap.runtime.as_ref();
            let facts = runtime.and_then(|r| r.admin_profile(host.as_str(), port, req.client_ip));
            if service_principal && facts.is_none() {
                t.step(
                    "service_profile",
                    "fail",
                    Some("service_profile_absent"),
                    json!({}),
                );
                break 'decide v(Outcome::Deny, "service_profile_absent");
            }
            if let (Some(runtime), Some((facts, _))) = (runtime, facts) {
                service_profile = json!({
                    "service_id": facts.service_id,
                    "realm": facts.realm,
                    "connectors": facts.connectors,
                    "api_keys": facts.api_keys,
                    "composed": facts.composed,
                    "session_fallback": facts.session_fallback,
                    "networks_restricted": facts.networks_restricted,
                    "client_ip_permitted": facts.client_ip_permitted,
                    "eligibility_script": facts.eligibility_script,
                    "revision": snap.revision,
                });
                let fallback = !service_principal && facts.session_fallback;
                if !fallback {
                    current_aal = Some(0);
                    if !service_principal {
                        t.step(
                            "service_profile",
                            "fail",
                            Some("service_credential_required"),
                            json!({}),
                        );
                        break 'decide v(Outcome::Deny, "service_credential_required");
                    }
                    let id = subject_ref.as_deref().unwrap_or_default();
                    let now_ms = u64::try_from(now.0).unwrap_or(0);
                    if workload_principal {
                        use crate::auth_gateway::runtime::WorkloadVerdict as W;
                        let verdict = runtime.admin_explain_workload(
                            host.as_str(),
                            port,
                            id,
                            req.client_ip,
                            now_ms,
                        );
                        let code = match &verdict {
                            W::NoProfile => Some((Outcome::Deny, "service_profile_absent")),
                            W::NotConfigured => Some((Outcome::Deny, "service_principal_unknown")),
                            W::SubjectInvalid => Some((Outcome::Deny, "workload_subject_invalid")),
                            W::NetworkDenied => Some((Outcome::Deny, "network_denied")),
                            W::NamespaceNotAllowed => {
                                Some((Outcome::Deny, "workload_namespace_not_allowed"))
                            }
                            W::ServiceAccountNotAllowed => {
                                Some((Outcome::Deny, "workload_service_account_not_allowed"))
                            }
                            W::ServiceAccountAbsent => {
                                Some((Outcome::Deny, "workload_service_account_absent"))
                            }
                            W::KeysUnavailable => {
                                Some((Outcome::Unavailable, "workload_keys_unavailable"))
                            }
                            W::RevocationStale => {
                                Some((Outcome::Unavailable, "workload_revocation_stale"))
                            }
                            W::LegacyWindowExpired => {
                                Some((Outcome::Unavailable, "workload_legacy_window_expired"))
                            }
                            W::Allowed { .. } => None,
                        };
                        if let Some((outcome, code)) = code {
                            t.step("workload_credential", "fail", Some(code), json!({}));
                            break 'decide v(outcome, code);
                        }
                        if let W::Allowed {
                            verification,
                            network_evaluated,
                            revocation_evaluated,
                            spiffe_id,
                            principal,
                            subject_ref: wire_subject,
                        } = verdict
                        {
                            if !network_evaluated {
                                t.step("network", "skip", Some("network_not_evaluated"), json!({}));
                            }
                            if !revocation_evaluated {
                                t.step(
                                    "workload_revocation",
                                    "skip",
                                    Some("workload_revocation_not_evaluated"),
                                    json!({}),
                                );
                            }
                            t.step(
                                "workload_credential",
                                "pass",
                                Some("workload_token_not_simulated"),
                                json!({
                                    "connector": if verification == "tokenreview" { "kubernetes_tokenreview" } else { "kubernetes_workload" },
                                    "verification": verification,
                                    "spiffe_id": spiffe_id,
                                    "principal": principal,
                                    "subject_ref": wire_subject,
                                }),
                            );
                        }
                    } else {
                        let key = runtime.admin_explain_key(
                            host.as_str(),
                            port,
                            id,
                            req.client_ip,
                            now_ms,
                        );
                        let code = match key {
                            KeyVerdict::Allowed { network_evaluated } => {
                                if !network_evaluated {
                                    t.step(
                                        "network",
                                        "skip",
                                        Some("network_not_evaluated"),
                                        json!({}),
                                    );
                                }
                                None
                            }
                            KeyVerdict::NoProfile => {
                                Some((Outcome::Deny, "service_profile_absent"))
                            }
                            KeyVerdict::Composition => {
                                Some((Outcome::Indeterminate, "remote_verifier"))
                            }
                            KeyVerdict::NotConfigured
                                if facts.connectors.iter().any(|c| *c != "api_key") =>
                            {
                                Some((Outcome::Indeterminate, "remote_verifier"))
                            }
                            KeyVerdict::NotConfigured => {
                                Some((Outcome::Deny, "service_principal_unknown"))
                            }
                            KeyVerdict::Expired => Some((Outcome::Deny, "credential_expired")),
                            KeyVerdict::NetworkDenied => Some((Outcome::Deny, "network_denied")),
                            KeyVerdict::Ineligible => Some((Outcome::Deny, "eligibility_denied")),
                            KeyVerdict::Unavailable => {
                                Some((Outcome::Unavailable, "eligibility_unavailable"))
                            }
                        };
                        if let Some((outcome, code)) = code {
                            t.step("service_credential", "fail", Some(code), json!({}));
                            break 'decide v(outcome, code);
                        }
                        t.step(
                            "service_credential",
                            "pass",
                            None,
                            json!({"connector": "api_key"}),
                        );
                    }
                    // The live path resolves the application after the
                    // credential, without the return-target checks.
                    let app = match apps::resolve(&snapshot, &host) {
                        Ok(app) => app,
                        Err(r) => {
                            let code = if r == reasons::APP_DISABLED {
                                "app_disabled"
                            } else {
                                "unknown_app"
                            };
                            t.step("application", "fail", Some(code), json!({}));
                            break 'decide v(Outcome::Deny, code);
                        }
                    };
                    application = app_json(app, &snapshot);
                    required_aal = app
                        .step_up
                        .iter()
                        .filter(|r| step_up::rule_matches(r, env.path.as_str()))
                        .map(|r| aal_num(r.aal))
                        .max()
                        .unwrap_or(1);
                    if app
                        .step_up
                        .iter()
                        .any(|r| step_up::rule_matches(r, env.path.as_str()))
                    {
                        t.step("step_up", "fail", Some("machine_step_up"), json!({}));
                        break 'decide v(Outcome::Deny, "machine_step_up");
                    }
                    break 'decide v(Outcome::Allow, "allowed");
                }
                t.step(
                    "service_profile",
                    "info",
                    None,
                    json!({"session_fallback": true}),
                );
            }
        }
        if url.scheme() == "http" && limits.secure {
            t.step("transport", "fail", Some("insecure_transport"), json!({}));
            break 'decide v(Outcome::Deny, "insecure_transport");
        }
        let validated = if matches!(env.path.reserved(), Reserved::Entry(_)) {
            let mut root = url.clone();
            root.set_path("/");
            root.set_query(None);
            root
        } else {
            url.clone()
        };
        if let Err(r) = apps::validate_return_target(validated.as_str(), &snapshot, limits.secure) {
            let code = match r.0 {
                "unknown_app" => "unknown_app",
                "app_disabled" => "app_disabled",
                "port_not_allowed" => "port_not_allowed",
                "insecure_transport" | "scheme" => "insecure_transport",
                _ => "contract_violation",
            };
            t.step("application", "fail", Some(code), json!({"cause": r.0}));
            break 'decide v(Outcome::Deny, code);
        }
        let app = match apps::resolve(&snapshot, &host) {
            Ok(app) => app,
            Err(r) => {
                let code = if r == reasons::APP_DISABLED {
                    "app_disabled"
                } else {
                    "unknown_app"
                };
                t.step("application", "fail", Some(code), json!({}));
                break 'decide v(Outcome::Deny, code);
            }
        };
        application = app_json(app, &snapshot);
        required_aal = app
            .step_up
            .iter()
            .filter(|r| step_up::rule_matches(r, env.path.as_str()))
            .map(|r| aal_num(r.aal))
            .max()
            .unwrap_or(1);
        t.step(
            "application",
            "pass",
            None,
            json!({"app_id": app.app_id.as_str()}),
        );
        match env.path.reserved() {
            Reserved::No => {}
            Reserved::Other => {
                t.step("reserved", "fail", Some("reserved_path"), json!({}));
                break 'decide v(Outcome::Deny, "reserved_path");
            }
            Reserved::Entry(_) => {
                t.step("reserved", "info", Some("entry_point"), json!({}));
                break 'decide v(Outcome::NotApplicable, "entry_point");
            }
        }

        // A browser session, when one was named.
        let live = match &session {
            Some(s) => {
                let (verdict, handle, step, fresh) =
                    evaluate_session(&mut t, &env, c, app, s).await?;
                session_out = session_json(s, handle.as_ref(), false);
                if let Some(h) = &handle {
                    current_aal = Some(aal_num(h.issued_aal.min(s.aal)));
                }
                step_up_out = step;
                fresh_out = fresh;
                Some(verdict)
            }
            None => {
                if req.session_id.is_some() {
                    t.step("session", "fail", Some("unknown_handle"), json!({}));
                    Some(v(Outcome::Login, "unknown_handle"))
                } else {
                    t.step("session", "info", Some("login_required"), json!({}));
                    None
                }
            }
        };
        if let Some(verdict) = live
            && verdict.outcome != Outcome::Login
        {
            break 'decide verdict;
        }
        let now_verdict = live.unwrap_or(v(Outcome::Login, "login_required"));

        // What a sign-in would lead to: the same checks on the session a
        // fresh sign-in (or the stated hypothesis) creates.
        let mut later = Trace {
            lang: t.lang,
            steps: Vec::new(),
        };
        let after = match &person {
            Some(p) if p.user.is_none() => v(Outcome::Indeterminate, "subject_deleted"),
            Some(p)
                if now_verdict.code == "handle_absent"
                    && p.user
                        .as_ref()
                        .is_some_and(|u| u.status == UserStatus::Active) =>
            {
                // The portal hands the live session over: the same session,
                // a handle at the session's level (the portal handle's cap is
                // assumed to be the session's).
                let s = session.as_ref().ok_or_else(reads::invalid)?;
                let (verdict, step, fresh) = post_auth(&mut later, &env, app, s, s.aal);
                after_login = json!({
                    "basis": "handoff",
                    "session": session_json(s, None, false),
                    "step_up": step,
                    "freshness": fresh,
                });
                verdict
            }
            Some(p)
                if p.user
                    .as_ref()
                    .is_some_and(|u| u.status == UserStatus::Disabled) =>
            {
                v(Outcome::Deny, "user_disabled")
            }
            None if subject_ref.is_some() || req.session_id.is_some() => {
                v(Outcome::Indeterminate, "subject_unknown")
            }
            _ => {
                let (s, h) = hypothetical_session(&env, person.as_ref(), &hypothetical)?;
                let (verdict, step, fresh) =
                    post_auth(&mut later, &env, app, &s, h.issued_aal.min(s.aal));
                after_login = json!({
                    "basis": "sign_in",
                    "session": session_json(&s, Some(&h), true),
                    "step_up": step,
                    "freshness": fresh,
                });
                verdict
            }
        };
        let after_reason = later.reason(after.code);
        let mut block = if after_login.is_null() {
            json!({})
        } else {
            after_login.clone()
        };
        block["outcome"] = json!(after.outcome.as_str());
        block["reason"] = after_reason;
        block["trace"] = json!(later.steps);
        after_login = block;
        now_verdict
    };

    let status_code = verdict.status(document);
    let reason = t.reason(verdict.code);
    let subject = json!({
        "input": if req.session_id.is_some() { "session" } else if subject_ref.is_some() { "subject" } else { "anonymous" },
        "item": subject_item,
    });
    Ok(json!({
        "simulated": true,
        "evaluated_at": now.secs(),
        "config_generation": snapshot.generation,
        "service_profile_revision": profile_revision,
        "request": {
            "url": env.url.as_str(),
            "host": env.host.as_str(),
            "port": env.port,
            "path": env.path.as_str(),
            "navigation": if document { "document" } else { "other" },
            "client_ip": req.client_ip.map(|ip| ip.to_string()),
        },
        "outcome": verdict.outcome.as_str(),
        "status_code": status_code,
        "reason": reason,
        "application": application,
        "service_profile": service_profile,
        "subject": subject,
        "session": session_out,
        "providers": providers,
        "assurance": assurance_json(current_aal, required_aal, if service_principal { 0 } else { achievable }, totp_configured, totp_enrolled, &external),
        "step_up": step_up_out,
        "freshness": fresh_out,
        "after_login": after_login,
        "trace": t.steps,
    }))
}

pub async fn explain_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(r) = reads::limit(&st, &c, Op::Explain) {
        return r;
    }
    let bytes = match reads::json_body(&st, &c, &headers, body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let run = async {
        let mut req: Request = serde_json::from_slice(&bytes).map_err(|_| reads::invalid())?;
        req.privacy_profile = req.privacy_profile.at_least(st.cfg.privacy_floor);
        let session = req.session_id.clone();
        let answer = explain(&st, &c, req).await?;
        let user = answer["subject"]["item"]["user_id"]
            .as_str()
            .map(UserId::new);
        reads::audit(&st, &c, Op::Explain, &bytes, |b| {
            let mut b = b
                .attr("status", answer["outcome"].as_str().unwrap_or_default())
                .attr(
                    "host",
                    answer["request"]["host"].as_str().unwrap_or_default(),
                )
                .attr("port", answer["request"]["port"].clone())
                .attr("navigation", answer["request"]["navigation"].clone());
            if let Some(app) = answer["application"]["app_id"].as_str() {
                b = b.attr("app", app);
            }
            if let Some(u) = &user {
                b = b.user(u);
            }
            if let Some(s) = &session {
                b = b.session(&SessionId::new(s.clone()));
            }
            b
        })
        .await?;
        Ok::<_, Fail>(api::json(StatusCode::OK, &answer))
    };
    let mut r = run.await.unwrap_or_else(|f| f.respond(&st, &c));
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}
