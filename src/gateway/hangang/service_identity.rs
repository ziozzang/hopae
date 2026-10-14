//! Service credentials use the same caller and request-context validation as sessions.
use crate::auth_gateway::{Subject, VerifiedEvidence};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Response, StatusCode},
};

#[derive(Debug, Clone, Copy)]
pub struct InvalidBearer;
pub fn bearer(headers: &HeaderMap) -> Result<Option<&str>, InvalidBearer> {
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(InvalidBearer);
    }
    let value = value.to_str().map_err(|_| InvalidBearer)?;
    let (scheme, token) = value.split_once(' ').ok_or(InvalidBearer)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(InvalidBearer);
    }
    Ok(Some(token))
}
pub fn stable_subject(subject: &Subject) -> String {
    crate::auth_gateway::stable_subject(subject)
}

pub fn response(evidence: Option<&VerifiedEvidence>, request_id: &str) -> Response<Body> {
    let kind = match evidence.map(|e| e.subject().kind) {
        Some(crate::auth_gateway::PrincipalKind::Service) => "service",
        Some(crate::auth_gateway::PrincipalKind::Workload) => "workload",
        Some(_) => return response(None, request_id),
        None => "service",
    };
    let mut response = Response::builder()
        .status(if evidence.is_some() {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        })
        .body(Body::empty())
        .expect("fixed service response");
    let headers = response.headers_mut();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("x-hopae-request-id", value);
    }
    if let Some(evidence) = evidence {
        let subject = evidence.subject();
        if let Some(service) = evidence.service() {
            headers.insert(
                "x-hopae-service-id",
                HeaderValue::from_str(service).expect("configured service identifier"),
            );
        }
        headers.insert(
            "x-forwarded-user",
            HeaderValue::from_str(&stable_subject(subject)).expect("encoded service identifier"),
        );
        headers.insert("x-hopae-principal-kind", HeaderValue::from_static(kind));
        headers.insert("x-hopae-aal", HeaderValue::from_static("0"));
    } else {
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer"),
        );
    }
    response
}

pub fn unavailable(request_id: &str) -> Response<Body> {
    let mut response = response(None, request_id);
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
        .headers_mut()
        .remove(http::header::WWW_AUTHENTICATE);
    response
        .headers_mut()
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}
