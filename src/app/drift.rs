//! Phase 0 of ADR-0012: with a read-only gateway credential, warn about
//! application hosts that have no route on the gateway. Read-only; the full
//! drift report is M2. Not wired to a configuration key yet: it needs
//! `gateway.admin_url` (a request to the configuration owner).

use std::collections::BTreeSet;
use std::time::Duration;

const LIMIT: usize = 1024 * 1024;

fn hosts_in(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Array(items) => items.iter().for_each(|v| hosts_in(v, out)),
        serde_json::Value::Object(map) => {
            if let Some(h) = map.get("host").and_then(|h| h.as_str()) {
                out.insert(h.to_ascii_lowercase());
            }
            for key in ["routes", "items", "data", "http"] {
                if let Some(v) = map.get(key) {
                    hosts_in(v, out);
                }
            }
        }
        _ => {}
    }
}

/// `GET <admin_url>/v1/routes/http` with the bearer token, then one warning
/// per application host that no route names. A failure to ask is itself a
/// warning, never an error. The token is never printed.
pub async fn drift_warnings(admin_url: &str, token: &str, app_hosts: &[String]) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec!["gateway drift check skipped: no HTTP client".to_string()],
    };
    let url = format!("{}/v1/routes/http", admin_url.trim_end_matches('/'));
    let resp = match client.get(&url).bearer_auth(token).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            return vec![format!(
                "gateway drift check skipped: {url} answered {}",
                r.status().as_u16()
            )];
        }
        Err(_) => return vec![format!("gateway drift check skipped: {url} not reachable")],
    };
    let body = match resp.bytes().await {
        Ok(b) if b.len() <= LIMIT => b,
        _ => {
            return vec!["gateway drift check skipped: unreadable or oversized answer".to_string()];
        }
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return vec!["gateway drift check skipped: answer is not JSON".to_string()];
    };
    let mut routed = BTreeSet::new();
    hosts_in(&json, &mut routed);
    app_hosts
        .iter()
        .filter(|h| !routed.contains(&h.to_ascii_lowercase()))
        .map(|h| format!("application host {h} has no route on the gateway"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::get;

    async fn serve(body: &'static str, expect_token: &'static str) -> String {
        let app = Router::new().route(
            "/v1/routes/http",
            get(move |h: HeaderMap| async move {
                let ok = h
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == format!("Bearer {expect_token}"));
                if ok {
                    (axum::http::StatusCode::OK, body)
                } else {
                    (axum::http::StatusCode::UNAUTHORIZED, "")
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn hosts_without_a_route_are_reported() {
        let url = serve(
            r#"[{"id":"a","host":"app.example.test"},{"id":"p","host":"auth.example.test"}]"#,
            "tok",
        )
        .await;
        let hosts = vec![
            "app.example.test".to_string(),
            "other.example.test".to_string(),
        ];
        let w = drift_warnings(&url, "tok", &hosts).await;
        assert_eq!(
            w,
            vec!["application host other.example.test has no route on the gateway"]
        );
    }

    #[tokio::test]
    async fn a_refused_or_unreachable_gateway_is_a_warning_without_the_token() {
        let url = serve("[]", "right").await;
        let w = drift_warnings(&url, "secret-token-value", &["a.test".into()]).await;
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("401") && !w[0].contains("secret-token-value"),
            "{w:?}"
        );
        let w = drift_warnings("http://127.0.0.1:1", "t", &["a.test".into()]).await;
        assert!(w[0].contains("not reachable"), "{w:?}");
    }
}
