//! Reference-only profile inspection behind the existing console authentication gate.
use super::{AdminState, Ctx, api};
use axum::{
    Extension,
    extract::State,
    http::{StatusCode, header},
    response::Response,
};
use std::sync::Arc;

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Extension(_context): Extension<Ctx>,
) -> Response {
    let permit = match state.profile_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    };
    let store = state.profile_store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::auth_gateway::publication::read(&store.conn())
    });
    let result = tokio::time::timeout(state.cfg.query_budget, task).await;
    let mut response = match result {
        Ok(Ok(Ok(Some(document)))) => match serde_json::to_value(&document) {
            Ok(value) => {
                let mut response = api::json(StatusCode::OK, &value);
                if let Ok(etag) = format!("\"{}\"", document.revision).parse() {
                    response.headers_mut().insert(header::ETAG, etag);
                }
                response
            }
            Err(_) => api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
        },
        Ok(Ok(Ok(None))) => api::json(
            StatusCode::OK,
            &serde_json::json!({"revision":0,"configuration":null}),
        ),
        _ => api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// The listener has authenticated the actor and supplied a CSRF/role-checked mutation.
pub async fn put(
    State(state): State<Arc<AdminState>>,
    Extension(context): Extension<Ctx>,
    Extension(mutation): Extension<super::csrf::Mutation>,
    headers: axum::http::HeaderMap,
) -> Response {
    let mut matches = headers.get_all(header::IF_MATCH).iter();
    let expected = match (matches.next(), matches.next()) {
        (Some(value), None) => value.to_str().ok().and_then(|value| {
            value
                .strip_prefix('"')?
                .strip_suffix('"')?
                .parse::<u64>()
                .ok()
        }),
        _ => None,
    };
    let Some(expected) = expected else {
        return api::json_error(StatusCode::PRECONDITION_REQUIRED, "revision_required");
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        configuration: serde_json::Value,
    }
    let input = match serde_json::from_slice::<Input>(&mutation.body) {
        Ok(input) => input,
        Err(_) => return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_profiles"),
    };
    let configuration = match serde_json::from_value::<Option<crate::auth_gateway::runtime::Config>>(
        input.configuration,
    ) {
        Ok(configuration) => configuration,
        Err(_) => return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_profiles"),
    };
    let Some(authority) = state.profile_authority.clone() else {
        return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable");
    };
    let permit = match state.profile_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    };
    let actor = api::actor(&context.principal);
    let policy = api::actor_policy(&state, &context.principal);
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut authority = authority
            .lock()
            .map_err(|_| crate::auth_gateway::publication::Error::Storage)?;
        let validate = |profiles: &crate::auth_gateway::runtime::Config| {
            let declared = state.profile_config.authentication_gateway.as_ref();
            for profile in &profiles.profiles {
                for key in &profile.api_keys {
                    if !declared.is_some_and(|config| {
                        config.profiles.iter().any(|old| {
                            old.api_keys
                                .iter()
                                .any(|reference| reference.token_env == key.token_env)
                        })
                    }) {
                        return Err(crate::auth_gateway::publication::Error::Invalid);
                    }
                }
                if let Some(relay) = &profile.api_relay {
                    let matching = declared.is_some_and(|config| {
                        config.profiles.iter().any(|old| {
                            old.api_relay.as_ref().is_some_and(|reference| {
                                reference.url == relay.url
                                    && reference.issuer == relay.issuer
                                    && reference.verifier_key_env == relay.verifier_key_env
                                    && reference.allow_private_endpoints
                                        == relay.allow_private_endpoints
                            })
                        })
                    });
                    if (relay.verifier_key_env.is_some() || relay.allow_private_endpoints)
                        && !matching
                    {
                        return Err(crate::auth_gateway::publication::Error::Invalid);
                    }
                }
            }
            let mut candidate = (*state.profile_config).clone();
            candidate.authentication_gateway = Some(profiles.clone());
            candidate
                .validate()
                .map_err(|_| crate::auth_gateway::publication::Error::Invalid)
        };
        let guard = |connection: &rusqlite::Connection| {
            state
                .profile_store
                .fence_profile_actor(connection, &actor, &policy)
                .map_err(|error| match error {
                    crate::store::StoreError::Conflict(_) => {
                        crate::auth_gateway::publication::Error::Denied
                    }
                    _ => crate::auth_gateway::publication::Error::Storage,
                })
        };
        let mut connection = state.profile_store.conn();
        authority.publish_authorized(
            &mut connection,
            expected,
            configuration,
            crate::auth_gateway::authority::Authorization {
                actor: actor.user_id.as_str(),
                guard: &guard,
            },
            &|name| std::env::var(name).ok(),
            &validate,
        )
    });
    match task.await {
        Ok(Ok(document)) => api::json(
            StatusCode::OK,
            &serde_json::json!({"revision":document.revision,"digest":document.digest}),
        ),
        Ok(Err(crate::auth_gateway::publication::Error::Conflict)) => {
            api::json_error(StatusCode::CONFLICT, "revision_conflict")
        }
        Ok(Err(crate::auth_gateway::publication::Error::Denied)) => {
            api::json_error(StatusCode::FORBIDDEN, "actor_revoked")
        }
        Ok(Err(crate::auth_gateway::publication::Error::Invalid)) => {
            api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_profiles")
        }
        _ => api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    }
}
