//! `GET /v1/me`: the signed-in administrator, as authentication resolved them.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use super::{AdminState, Ctx, api};

pub async fn get(State(_st): State<Arc<AdminState>>, ctx: Ctx) -> Response {
    let p = &ctx.principal;
    api::json(
        StatusCode::OK,
        &serde_json::json!({
            "user_id": p.user_id.as_str(),
            "email": p.email.as_ref().map(|e| e.as_str()),
            "display_name": p.display_name,
            "role": p.role.as_str(),
            "session_id": p.session_id.as_str(),
            "auth_time": p.auth_time.secs(),
            "auth_time_source": p.auth_time_source.as_str(),
            "aal": p.aal.as_i64(),
        }),
    )
}
