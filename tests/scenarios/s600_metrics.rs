//! Scenario 600: the OpenMetrics exposition on the admin listener, read by a
//! route-scoped service credential (`--preset metrics`) over mutual TLS.
use super::s318_service_credentials::{AUDIENCE, Fx, SAN};
use hopae::app::ServiceCredentialCommand;

async fn scrape(fx: &Fx, token: Option<&str>) -> (u16, String, String) {
    scrape_with(fx, token, Some(AUDIENCE)).await
}

async fn scrape_with(
    fx: &Fx,
    token: Option<&str>,
    audience: Option<&str>,
) -> (u16, String, String) {
    let client = fx.client(Some(&fx.pki.client));
    let url = format!(
        "https://{}:{}/metrics",
        super::s318_service_credentials::ADMIN_HOST,
        fx.addr.port()
    );
    let mut r = client.get(&url);
    if let Some(a) = audience {
        r = r.header("x-hopae-audience", a);
    }
    if let Some(t) = token {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = r.send().await.unwrap();
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, ctype, resp.text().await.unwrap())
}

/// S600-1: the `metrics` preset scrapes `/metrics` (OpenMetrics, `# EOF`)
/// with the hot-path families, the latency histograms, the store-derived
/// gauges and the TLS leaf expiry; no subject or address appears.
#[tokio::test(flavor = "multi_thread")]
async fn s600_1_metrics_preset_scrapes_openmetrics_over_mtls() {
    let fx = Fx::start(true).await;
    let token = fx
        .create("prometheus", |cmd| {
            if let ServiceCredentialCommand::Create { routes, preset, .. } = cmd {
                routes.clear();
                *preset = Some("metrics".into());
            }
        })
        .await;
    let (status, ctype, body) = scrape(&fx, Some(&token)).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        ctype.starts_with("application/openmetrics-text; version=1.0.0"),
        "{ctype}"
    );
    assert!(body.ends_with("# EOF\n"));
    for family in [
        "# TYPE hopae_auth_outcomes counter",
        "# TYPE hopae_verify_duration_seconds histogram",
        "# TYPE hopae_grpc_requests counter",
        "# TYPE hopae_sessions_created counter",
        "# TYPE hopae_stepup_results counter",
        "# TYPE hopae_passkey_ceremonies counter",
        "# TYPE hopae_rate_limited counter",
        "# TYPE hopae_store_failures counter",
        "hopae_store_up 1",
        "hopae_sessions_active ",
        "hopae_projection_feed_rows ",
        "hopae_lifecycle_feed_head{source=\"outbox\"}",
        "# TYPE hopae_event_relay_backlog gauge",
        "hopae_verify_duration_seconds_bucket{surface=\"forward_auth\",le=\"+Inf\"}",
    ] {
        assert!(body.contains(family), "missing {family}\n{body}");
    }
    // The admin listener's own certificate expires in about a day.
    let expiry: i64 = body
        .lines()
        .find(|l| l.starts_with("hopae_tls_leaf_expiry_seconds{name=\"admin\"}"))
        .and_then(|l| l.rsplit_once(' '))
        .map(|(_, v)| v.parse().unwrap())
        .expect("admin leaf expiry");
    assert!((80_000..=86_400).contains(&expiry), "{expiry}");
    // Each family is declared once.
    let types: Vec<&str> = body.lines().filter(|l| l.starts_with("# TYPE ")).collect();
    let mut unique = types.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(types.len(), unique.len());
    assert!(!body.contains(SAN) && !body.contains("127.0.0.1") && !body.contains('@'));
    // The scrape answers again (the series persist; nothing is consumed),
    // also without the audience header a ServiceMonitor cannot send; a
    // foreign audience is still refused.
    assert_eq!(scrape_with(&fx, Some(&token), None).await.0, 200);
    assert_eq!(
        scrape_with(&fx, Some(&token), Some("https://other.example.test"))
            .await
            .0,
        403
    );
    fx.stop().await;
}

/// S600-2: without a credential, with a credential that lacks the route,
/// and with the metrics credential on another route, the listener refuses.
#[tokio::test(flavor = "multi_thread")]
async fn s600_2_metrics_needs_the_route_and_the_credential_opens_nothing_else() {
    let fx = Fx::start(true).await;
    let metrics = fx
        .create("prometheus", |cmd| {
            if let ServiceCredentialCommand::Create { routes, preset, .. } = cmd {
                routes.clear();
                *preset = Some("metrics".into());
            }
        })
        .await;
    let pumgye = fx.create("pumgye-v2", |_| {}).await;
    let (status, _, _) = scrape(&fx, None).await;
    // No bearer and no console session: the console answers as for any
    // unauthenticated request, never with metrics.
    assert!(matches!(status, 401 | 403 | 404), "{status}");
    let (status, _, _) = scrape(&fx, Some(&pumgye)).await;
    assert_eq!(status, 403);
    let client = fx.client(Some(&fx.pki.client));
    let status = client
        .get(format!(
            "https://{}:{}/v1/status",
            super::s318_service_credentials::ADMIN_HOST,
            fx.addr.port()
        ))
        .header("x-hopae-audience", AUDIENCE)
        .header("authorization", format!("Bearer {metrics}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 403);
    fx.stop().await;
}
