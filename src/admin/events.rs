//! `/events` and `/v1/events` handlers (W1-B). W0 ships stubs that answer
//! `501 not_implemented`, so the router compiles before W1-B lands.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::AdminState;

fn not_implemented() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [("content-type", "application/json")],
        r#"{"error":"not_implemented"}"#,
    )
        .into_response()
}

macro_rules! stubs {
    ($($name:ident),+ $(,)?) => {
        $(pub async fn $name(State(_): State<Arc<AdminState>>) -> Response { not_implemented() })+
    };
}

stubs!(list_page, list_api);
