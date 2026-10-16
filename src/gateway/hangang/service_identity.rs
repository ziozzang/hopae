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
/// Explicit typed service ingress; legacy bearer() still accepts Bearer only.
pub(crate) fn credential(
    headers: &HeaderMap,
) -> Result<Option<crate::auth_gateway::composition::Credential<'_>>, InvalidBearer> {
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(InvalidBearer);
    }
    let value = value.to_str().map_err(|_| InvalidBearer)?;
    let (scheme, token) = value.split_once(' ').ok_or(InvalidBearer)?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(InvalidBearer);
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        Ok(Some(crate::auth_gateway::composition::Credential::Bearer(
            token,
        )))
    } else if scheme.eq_ignore_ascii_case("hopae-compose") && token.len() <= 4096 {
        Ok(Some(
            crate::auth_gateway::composition::Credential::Composite(token),
        ))
    } else {
        Err(InvalidBearer)
    }
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
        // Kubernetes workload identity (Hangang ADR 0021/0022): the
        // ServiceAccount-scoped principal and its SPIFFE ID, shared with
        // Hangang's workload mTLS. Outputs of verification, never inputs.
        if let Some(workload) = evidence.workload() {
            if let Ok(value) = HeaderValue::from_str(&workload.principal) {
                headers.insert("x-hopae-principal", value);
            }
            if let Some(value) = workload
                .spiffe_id
                .as_deref()
                .and_then(|id| HeaderValue::from_str(id).ok())
            {
                headers.insert("x-hopae-workload-spiffe-id", value);
            }
        }
    } else {
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer"),
        );
    }
    response
}

/// Export remaining evidence lifetime without transferring credentials or a decision cache.
pub fn response_at(
    evidence: Option<&VerifiedEvidence>,
    request_id: &str,
    now_ms: u64,
) -> Response<Body> {
    if evidence.is_some_and(|e| e.expires_at_ms() <= now_ms) {
        return unavailable(request_id);
    }
    let mut reply = response(evidence, request_id);
    if reply.status() == StatusCode::OK {
        let remaining = evidence
            .unwrap()
            .expires_at_ms()
            .saturating_sub(now_ms)
            .min(1000);
        reply.headers_mut().insert(
            "x-hopae-evidence-ttl-ms",
            HeaderValue::from_str(&remaining.to_string()).expect("bounded lifetime"),
        );
    }
    reply
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remaining_evidence_lifetime_is_bounded_and_expired_identity_is_absent() {
        let key = "owned-test-service-key-at-least-thirty-two";
        let config = serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"api.example.test","ports":[443],"realm":"owned","api_keys":[{"token_env":"FIXTURE_KEY","subject":"worker"}]}]})).unwrap();
        let runtime = crate::auth_gateway::runtime::Runtime::compile(&config, &|name| {
            (name == "FIXTURE_KEY").then(|| key.to_owned())
        })
        .unwrap();
        let evidence = runtime
            .authenticate(
                "api.example.test",
                443,
                Some(key),
                "127.0.0.1".parse().unwrap(),
                100,
            )
            .unwrap();
        let reply = response_at(Some(&evidence), "fixture", 1001);
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()["x-hopae-evidence-ttl-ms"], "99");
        assert_eq!(
            response_at(Some(&evidence), "fixture", 0).headers()["x-hopae-evidence-ttl-ms"],
            "1000"
        );
        let expired = response_at(Some(&evidence), "fixture", 1100);
        assert_eq!(expired.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!expired.headers().contains_key("x-forwarded-user"));
        assert!(!expired.headers().contains_key("x-hopae-evidence-ttl-ms"));
    }
}
