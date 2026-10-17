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
            Ok(mut value) => {
                value["source"] = state.profile_config.authentication.source.as_str().into();
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
            &serde_json::json!({"revision":0,"configuration":null,
                "source": state.profile_config.authentication.source.as_str()}),
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
    // `authentication.source = config`: the file owns this document; an edit
    // here would be undone at the next start, so it is refused outright.
    if state.profile_config.authentication.source == crate::config::AuthenticationSource::Config {
        return api::json_error(StatusCode::CONFLICT, "config_authoritative");
    }
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
        // Read by `reason_of`.
        #[serde(default)]
        #[allow(dead_code)]
        reason: Option<serde_json::Value>,
    }
    let input = match serde_json::from_slice::<Input>(&mutation.body) {
        Ok(input) => input,
        Err(_) => return api::json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_profiles"),
    };
    let reason = match super::users::common::reason_of(&mutation) {
        Ok(r) => r,
        Err(f) => return f.respond(&state, &context),
    };
    let event = super::users::with_note(
        super::users::common::admin_event(
            &state,
            &context,
            crate::event::types::EventKind::AdminProfilesPublish,
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
            if reference_issues(&state, profiles).is_empty() {
                let mut candidate = (*state.profile_config).clone();
                candidate.authentication_gateway = Some(profiles.clone());
                candidate
                    .validate()
                    .map_err(|_| crate::auth_gateway::publication::Error::Invalid)
            } else {
                Err(crate::auth_gateway::publication::Error::Invalid)
            }
        };
        // The guard runs inside the publication's transaction, before and
        // after its writes: the fence both times, and the `admin.*` record
        // once, so a refused or conflicting publication rolls it back too.
        let recorded = std::cell::Cell::new(false);
        let guard = |connection: &rusqlite::Connection| {
            state
                .profile_store
                .fence_profile_actor(connection, &actor, &policy)
                .map_err(|error| match error {
                    crate::store::StoreError::Conflict(_) => {
                        crate::auth_gateway::publication::Error::Denied
                    }
                    _ => crate::auth_gateway::publication::Error::Storage,
                })?;
            if !recorded.get() {
                state
                    .profile_store
                    .record_in(connection, std::slice::from_ref(&event))
                    .map_err(|_| crate::auth_gateway::publication::Error::Storage)?;
                recorded.set(true);
            }
            Ok(())
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
        Ok(Ok(document)) => {
            super::users::common::count_event(
                crate::event::types::EventKind::AdminProfilesPublish,
                crate::event::types::Outcome::Success,
            );
            api::json(
                StatusCode::OK,
                &serde_json::json!({"revision":document.revision,"digest":document.digest}),
            )
        }
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

/// One finding of a profile validation: where (a JSON path into the posted
/// `configuration`, `""` for the whole document), a stable code and an
/// operator-facing message. Never a secret value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Issue {
    pub path: String,
    pub code: &'static str,
    pub message: String,
}

impl Issue {
    fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Issue {
        Issue {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// References a console publication may not introduce: an API key variable
/// or a relay trust setting the operator's file does not declare.
fn reference_issues(
    state: &AdminState,
    profiles: &crate::auth_gateway::runtime::Config,
) -> Vec<Issue> {
    let declared = state.profile_config.authentication_gateway.as_ref();
    let mut out = Vec::new();
    for (i, profile) in profiles.profiles.iter().enumerate() {
        for (j, key) in profile.api_keys.iter().enumerate() {
            if !declared.is_some_and(|config| {
                config.profiles.iter().any(|old| {
                    old.api_keys
                        .iter()
                        .any(|reference| reference.token_env == key.token_env)
                })
            }) {
                out.push(Issue::new(
                    format!("profiles[{i}].api_keys[{j}].token_env"),
                    "undeclared_reference",
                    "an API key variable must already be declared in the configuration file",
                ));
            }
        }
        if let Some(relay) = &profile.api_relay {
            let matching = declared.is_some_and(|config| {
                config.profiles.iter().any(|old| {
                    old.api_relay.as_ref().is_some_and(|reference| {
                        reference.url == relay.url
                            && reference.ca_file == relay.ca_file
                            && reference.issuer == relay.issuer
                            && reference.verifier_key_env == relay.verifier_key_env
                            && reference.allow_private_endpoints == relay.allow_private_endpoints
                    })
                })
            });
            if (relay.verifier_key_env.is_some()
                || relay.allow_private_endpoints
                || relay.ca_file.is_some())
                && !matching
            {
                out.push(Issue::new(
                    format!("profiles[{i}].api_relay"),
                    "undeclared_reference",
                    "a relay with a verifier key, a CA file or private endpoints must match one declared in the configuration file",
                ));
            }
        }
    }
    out
}

/// Every finding a publication of `value` would be refused for, in the order
/// the publication checks them: the document's shape (with the path of the
/// first mismatch), undeclared references, then each profile against the
/// runtime and the configuration rules (a finding no single profile explains
/// is reported for the whole document), then compilation.
pub fn validate_document(state: &AdminState, value: serde_json::Value) -> Vec<Issue> {
    if value.is_null() {
        // Publishing `null` disables the gateway: always valid.
        return Vec::new();
    }
    let config: crate::auth_gateway::runtime::Config = match serde_path_to_error::deserialize(value)
    {
        Ok(c) => c,
        Err(e) => {
            let path = e.path().to_string();
            let path = if path == "." { String::new() } else { path };
            return vec![Issue::new(path, "invalid_document", e.inner().to_string())];
        }
    };
    let mut out = reference_issues(state, &config);
    let with = |profiles: Vec<crate::auth_gateway::runtime::Profile>| {
        crate::auth_gateway::runtime::Config {
            authority_id: config.authority_id.clone(),
            profiles,
        }
    };
    let file_rules = |candidate_gateway: &crate::auth_gateway::runtime::Config| {
        let mut candidate = (*state.profile_config).clone();
        candidate.authentication_gateway = Some(candidate_gateway.clone());
        match candidate.validate() {
            Ok(()) => Vec::new(),
            Err(crate::config::ConfigError::Invalid(errs)) => errs,
            Err(other) => vec![other.to_string()],
        }
    };
    let mut attributed = false;
    for (i, profile) in config.profiles.iter().enumerate() {
        let single = with(vec![profile.clone()]);
        if let Err(e) = single.validate() {
            out.push(Issue::new(
                format!("profiles[{i}]"),
                "invalid_profile",
                e.to_string(),
            ));
            attributed = true;
            continue;
        }
        for message in file_rules(&single) {
            out.push(Issue::new(
                format!("profiles[{i}]"),
                "configuration_rule",
                message,
            ));
            attributed = true;
        }
    }
    if !attributed {
        if let Err(e) = config.validate() {
            out.push(Issue::new("", "invalid_configuration", e.to_string()));
        } else {
            for message in file_rules(&config) {
                out.push(Issue::new("", "configuration_rule", message));
            }
        }
    }
    if out.is_empty()
        && let Err(e) = crate::auth_gateway::runtime::Runtime::compile(&config, &|name| {
            std::env::var(name).ok()
        })
    {
        out.push(Issue::new("", "compile_failed", e.to_string()));
    }
    out
}

/// `POST /v1/authentication/profiles/validate` with `{"configuration": …}`:
/// the checks a publication runs, without publishing. `200` with
/// `{"valid": bool, "errors": [{"path", "code", "message"}]}`; an audited
/// read (`profiles.validate`), rate-limited per actor, under the JSON API rule.
pub async fn validate_api(
    State(state): State<Arc<AdminState>>,
    context: super::Ctx,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Response {
    use super::reads::{self, Op};
    let bytes = match reads::json_body(&state, &context, &headers, body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Some(r) = reads::limit(&state, &context, Op::Validate) {
        return r;
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        configuration: serde_json::Value,
    }
    let Ok(input) = serde_json::from_slice::<Input>(&bytes) else {
        return api::json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let permit = match state.profile_workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    };
    let st = state.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        validate_document(&st, input.configuration)
    });
    let issues = match tokio::time::timeout(state.cfg.query_budget, task).await {
        Ok(Ok(issues)) => issues,
        _ => return api::json_error(StatusCode::SERVICE_UNAVAILABLE, "profiles_unavailable"),
    };
    if let Err(f) = reads::audit(&state, &context, Op::Validate, &bytes, |b| {
        b.attr("count", issues.len())
    })
    .await
    {
        return f.respond(&state, &context);
    }
    let mut r = api::json(
        StatusCode::OK,
        &serde_json::json!({"valid": issues.is_empty(), "errors": issues}),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    r
}
