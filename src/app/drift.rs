//! Phase 0 of ADR-0012: with a read-only gateway credential, warn about
//! application hosts that have no route on the gateway. Read-only; the full
//! drift report is M2. Not wired to a configuration key yet: it needs
//! `gateway.admin_url` (a request to the configuration owner).

use std::time::Duration;

const LIMIT: usize = 1024 * 1024;

/// The path the gateway's `auth.url` must end in for a route to count as
/// calling a Hopae verify endpoint (the address cannot be compared: the
/// gateway may reach Hopae under another name than `listen.gateway`).
const VERIFY_PATH: &str = "/_hopae/verify";

fn host_covers(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|label| label.ends_with('.') && label.len() > 1),
        None => pattern == host,
    }
}

/// Host patterns of every route whose `auth.url` is a Hopae verify endpoint.
fn authenticated_host_patterns(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .for_each(|v| authenticated_host_patterns(v, out)),
        serde_json::Value::Object(map) => {
            let calls_verify = map
                .get("auth")
                .and_then(|a| a.get("url"))
                .and_then(|u| u.as_str())
                .and_then(|u| url::Url::parse(u).ok())
                .is_some_and(|u| u.path() == VERIFY_PATH);
            if calls_verify {
                if let Some(h) = map.get("host").and_then(|h| h.as_str()) {
                    out.push(h.to_string());
                }
                if let Some(hs) = map.get("hosts").and_then(|h| h.as_array()) {
                    out.extend(hs.iter().filter_map(|h| h.as_str()).map(String::from));
                }
            }
            for key in ["routes", "items", "data", "http"] {
                if let Some(v) = map.get(key) {
                    authenticated_host_patterns(v, out);
                }
            }
        }
        _ => {}
    }
}

/// What the gateway's routes say about one host: the patterns of routes with
/// a Hopae `auth.url` that cover it, and whether any of them strips cookies.
fn console_route_facts(value: &serde_json::Value, host: &str, facts: &mut (bool, bool)) {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .for_each(|v| console_route_facts(v, host, facts)),
        serde_json::Value::Object(map) => {
            let calls_verify = map
                .get("auth")
                .and_then(|a| a.get("url"))
                .and_then(|u| u.as_str())
                .and_then(|u| url::Url::parse(u).ok())
                .is_some_and(|u| u.path() == VERIFY_PATH);
            let mut patterns: Vec<&str> = Vec::new();
            if let Some(h) = map.get("host").and_then(|h| h.as_str()) {
                patterns.push(h);
            }
            if let Some(hs) = map.get("hosts").and_then(|h| h.as_array()) {
                patterns.extend(hs.iter().filter_map(|h| h.as_str()));
            }
            if patterns.iter().any(|p| host_covers(p, host)) {
                if calls_verify {
                    facts.0 = true;
                }
                let strips = map
                    .get("strip_request_cookies")
                    .and_then(|c| c.as_array())
                    .is_some_and(|c| !c.is_empty());
                if strips {
                    facts.1 = true;
                }
            }
            for key in ["routes", "items", "data", "http"] {
                if let Some(v) = map.get(key) {
                    console_route_facts(v, host, facts);
                }
            }
        }
        _ => {}
    }
}

/// `GET <admin_url>/v1/routes/http` with the bearer token, then one warning
/// per (application, host) that no route with a Hopae `auth.url` covers
/// (S008-5). A failure to ask is itself a warning, never an error. The token
/// is never printed. `apps` pairs each application id with its hosts.
pub async fn drift_warnings(
    admin_url: &str,
    token: &str,
    apps: &[(String, Vec<String>)],
) -> Vec<String> {
    drift_warnings_with_console(admin_url, token, apps, None).await
}

/// As [`drift_warnings`], and for the console host: `console_route_without_auth`
/// when no route with a Hopae `auth.url` covers it (every console request would
/// be refused), `console_route_strips_cookies` when a covering route sets
/// `strip_request_cookies` (the console would never see its handle).
pub async fn drift_warnings_with_console(
    admin_url: &str,
    token: &str,
    apps: &[(String, Vec<String>)],
    console_host: Option<&str>,
) -> Vec<String> {
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
    let mut routed = Vec::new();
    authenticated_host_patterns(&json, &mut routed);
    let mut out: Vec<String> = apps
        .iter()
        .flat_map(|(id, hosts)| hosts.iter().map(move |h| (id, h)))
        .filter(|(_, h)| !routed.iter().any(|p| host_covers(p, h)))
        .map(|(id, h)| {
            format!(
                "app {id}: no gateway route with auth.url pointing at this instance for host {h}"
            )
        })
        .collect();
    if let Some(host) = console_host {
        let mut facts = (false, false);
        console_route_facts(&json, host, &mut facts);
        if !facts.0 {
            out.push(format!(
                "console_route_without_auth: no gateway route with auth.url pointing at this instance for the console host {host}"
            ));
        }
        if facts.1 {
            out.push(format!(
                "console_route_strips_cookies: a gateway route for the console host {host} sets strip_request_cookies; the console would never see its handle cookie"
            ));
        }
    }
    out
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
            r#"[{"id":"a","host":"app.example.test","auth":{"url":"http://hopae:8701/_hopae/verify"}},
                {"id":"pub","host":"other.example.test","auth":null},
                {"id":"p","host":"auth.example.test"}]"#,
            "tok",
        )
        .await;
        let apps = vec![
            ("app".to_string(), vec!["app.example.test".to_string()]),
            ("other".to_string(), vec!["other.example.test".to_string()]),
        ];
        let w = drift_warnings(&url, "tok", &apps).await;
        assert_eq!(
            w,
            vec![
                "app other: no gateway route with auth.url pointing at this instance for host other.example.test"
            ],
            "a public route without auth does not protect the host"
        );
    }

    #[tokio::test]
    async fn the_console_route_needs_auth_and_must_not_strip_cookies() {
        let apps: Vec<(String, Vec<String>)> = Vec::new();
        let good = serve(
            r#"[{"id":"hopae-admin","host":"c.example.test","auth":{"url":"http://hopae:8701/_hopae/verify"}}]"#,
            "t",
        )
        .await;
        assert!(
            drift_warnings_with_console(&good, "t", &apps, Some("c.example.test"))
                .await
                .is_empty()
        );
        let bare = serve(r#"[{"id":"hopae-admin","host":"c.example.test"}]"#, "t").await;
        let w = drift_warnings_with_console(&bare, "t", &apps, Some("c.example.test")).await;
        assert_eq!(w.len(), 1);
        assert!(w[0].starts_with("console_route_without_auth"), "{w:?}");
        let strips = serve(
            r#"[{"id":"hopae-admin","host":"c.example.test","auth":{"url":"http://hopae:8701/_hopae/verify"},"strip_request_cookies":["__Host-hopae"]}]"#,
            "t",
        )
        .await;
        let w = drift_warnings_with_console(&strips, "t", &apps, Some("c.example.test")).await;
        assert_eq!(w.len(), 1);
        assert!(w[0].starts_with("console_route_strips_cookies"), "{w:?}");
        let none = serve("[]", "t").await;
        let w = drift_warnings_with_console(&none, "t", &apps, Some("c.example.test")).await;
        assert!(w[0].starts_with("console_route_without_auth"), "{w:?}");
    }

    #[tokio::test]
    async fn a_refused_or_unreachable_gateway_is_a_warning_without_the_token() {
        let url = serve("[]", "right").await;
        let apps = vec![("a".to_string(), vec!["a.test".to_string()])];
        let w = drift_warnings(&url, "secret-token-value", &apps).await;
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("401") && !w[0].contains("secret-token-value"),
            "{w:?}"
        );
        let w = drift_warnings("http://127.0.0.1:1", "t", &apps).await;
        assert!(w[0].contains("not reachable"), "{w:?}");
    }
}
