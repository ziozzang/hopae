//! Reference-only projection management using the existing role/CSRF/delegation gate.
use super::{AdminState, Ctx, api};
use axum::{
    Extension,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use std::sync::Arc;

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Extension(_context): Extension<Ctx>,
) -> Response {
    let permit = match state.profile_workers.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "projections_unavailable");
        }
    };
    let store = state.profile_store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        use crate::store::meta::MetaDb as _;
        store
            .meta()
            .meta_read(|tx| crate::auth_gateway::projection_authority::read(tx))
    });
    let mut response = match tokio::time::timeout(state.cfg.query_budget, task).await {
        Ok(Ok(Ok(document))) => {
            let revision = document.as_ref().map_or(0, |d| d.revision);
            let value = match document {
                Some(d) => match serde_json::to_value(d) {
                    Ok(v) => v,
                    Err(_) => {
                        return api::json_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "projections_unavailable",
                        );
                    }
                },
                None => serde_json::json!({"revision":0,"configuration":null}),
            };
            let mut response = api::json(StatusCode::OK, &value);
            if let Ok(etag) = format!("\"{revision}\"").parse() {
                response.headers_mut().insert(header::ETAG, etag);
            }
            response
        }
        _ => api::json_error(StatusCode::SERVICE_UNAVAILABLE, "projections_unavailable"),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
pub async fn put(
    State(state): State<Arc<AdminState>>,
    Extension(context): Extension<Ctx>,
    Extension(mutation): Extension<super::csrf::Mutation>,
    headers: HeaderMap,
) -> Response {
    // `authentication.source = config`: the file owns this document; an edit
    // here would be undone at the next start, so it is refused outright.
    if state.profile_config.authentication.source == crate::config::AuthenticationSource::Config {
        return api::json_error(StatusCode::CONFLICT, "config_authoritative");
    }
    let mut matches = headers.get_all(header::IF_MATCH).iter();
    let expected = match (matches.next(), matches.next()) {
        (Some(v), None) => v
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix('"')?.strip_suffix('"')?.parse::<u64>().ok()),
        _ => None,
    };
    let Some(expected) = expected else {
        return api::json_error(StatusCode::PRECONDITION_REQUIRED, "revision_required");
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        configuration: serde_json::Value,
        // Read by `reason_of`.
        #[serde(default)]
        #[allow(dead_code)]
        reason: Option<serde_json::Value>,
    }
    let input = match serde_json::from_slice::<Input>(&mutation.body) {
        Ok(input) => input,
        Err(_) => return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_projections"),
    };
    let reason = match super::users::common::reason_of(&mutation) {
        Ok(r) => r,
        Err(f) => return f.respond(&state, &context),
    };
    let event = super::users::with_note(
        super::users::common::admin_event(
            &state,
            &context,
            crate::event::types::EventKind::AdminProjectionsPublish,
            crate::event::types::Outcome::Success,
        ),
        reason.as_deref(),
    )
    .attr("revision", expected.saturating_add(1))
    .attr(
        "status",
        if input.configuration.is_null() {
            "disabled"
        } else {
            "enabled"
        },
    )
    .build();
    let configuration: Option<crate::auth_gateway::projection::Configuration> =
        match serde_json::from_value(input.configuration) {
            Ok(configuration) => configuration,
            Err(_) => {
                return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_projections");
            }
        };
    if let Some(config) = &configuration
        && (Some(config.revision) != expected.checked_add(1)
            || crate::auth_gateway::projection::validate_capabilities(
                config,
                state.profile_config.credential_projection.as_ref(),
            )
            .is_err())
    {
        return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_projections");
    }
    let permit = match state.profile_workers.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "projections_unavailable");
        }
    };
    let actor = api::actor(&context.principal);
    let policy = api::actor_policy(&state, &context.principal);
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut owner = state
            .projection_authority
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if owner.reader().load().revision() != expected {
            return Err(StatusCode::CONFLICT);
        }
        use crate::store::meta::MetaDb as _;
        let mut connection = state.profile_store.meta();
        let durable = connection
            .meta_read(|tx| crate::auth_gateway::projection_authority::read(tx))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if durable.as_ref().map_or(0, |d| d.revision) != expected {
            return Err(StatusCode::CONFLICT);
        }
        let denied = std::cell::Cell::new(false);
        // Inside the publication's transaction (before and after its
        // writes): the fence both times, the `admin.*` record once.
        let recorded = std::cell::Cell::new(false);
        let guard = |db: &dyn crate::store::meta::MetaTx| {
            state
                .profile_store
                .fence_meta(db, &actor, &policy)
                .map_err(|error| {
                    if matches!(error, crate::store::StoreError::Conflict(_)) {
                        denied.set(true);
                    }
                    crate::auth_gateway::receipt_keys::Refused
                })?;
            if !recorded.get() {
                state
                    .profile_store
                    .record_in(db, std::slice::from_ref(&event))
                    .map_err(|_| crate::auth_gateway::receipt_keys::Refused)?;
                recorded.set(true);
            }
            Ok(())
        };
        owner
            .publish(
                &mut connection,
                expected,
                configuration,
                actor.user_id.as_str(),
                &guard,
            )
            .map_err(|_| {
                if denied.get() {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            })
    });
    match task.await {
        Ok(Ok(d)) => {
            super::users::common::count_event(
                crate::event::types::EventKind::AdminProjectionsPublish,
                crate::event::types::Outcome::Success,
            );
            api::json(
                StatusCode::OK,
                &serde_json::json!({"revision":d.revision,"digest":d.digest}),
            )
        }
        Ok(Err(StatusCode::CONFLICT)) => api::json_error(StatusCode::CONFLICT, "revision_conflict"),
        Ok(Err(StatusCode::FORBIDDEN)) => api::json_error(StatusCode::FORBIDDEN, "actor_revoked"),
        _ => api::json_error(StatusCode::SERVICE_UNAVAILABLE, "projections_unavailable"),
    }
}
