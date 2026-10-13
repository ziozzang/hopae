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
