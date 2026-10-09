//! The verify listener end to end over a socket, with the real store and the
//! current `decide`: caller key, concurrency limit and routing.

use std::sync::Mutex;

use super::GatewayConfig;
use super::VERIFY_PATH;
use crate::config;
use crate::crypto::{SeededRng, SystemClock};
use crate::http::gateway::{CounterFn, GatewayState, router};
use crate::store::{Store, StoreHooks};
use crate::verify::types::VerifyContext;
use std::sync::Arc;

const KEY: &str = "unit-test-caller-key";

struct Fixture {
    base: String,
    hooks: Arc<StoreHooks>,
    counts: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

async fn serve(max_concurrent: u32) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config::parse(&format!(
        r#"{{"listen": {{"portal": "127.0.0.1:0", "gateway": "127.0.0.1:0"}},
            "state_dir": {:?},
            "portal": {{"public_url": "https://auth.example.test"}},
            "gateway": {{"kind": "hangang", "caller_key_env": "K"}},
            "apps": [{{"app_id": "app", "hosts": ["app.example.test"]}}]}}"#,
        dir.path().join("state").display().to_string()
    ))
    .unwrap();
    let hooks = Arc::new(StoreHooks::new());
    let store = Store::open(
        &dir.path().join("state/hopae.db"),
        Arc::new(SystemClock),
        vec!["log".into()],
        Some(hooks.clone()),
    )
    .unwrap();
    let ctx = VerifyContext::new(
        store.directory(),
        store.sessions(),
        Arc::new(SystemClock),
        Arc::new(SeededRng::new(1)),
        Arc::new(arc_swap::ArcSwap::from_pointee(cfg.snapshot(0))),
        cfg.verify_limits(),
    );
    let counts = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = counts.clone();
    let counters: CounterFn = Arc::new(move |name, labels| {
        let l: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        sink.lock()
            .unwrap()
            .push(format!("{name}{{{}}}", l.join(",")));
    });
    let gw = GatewayConfig::from_config(&cfg, |n| (n == "K").then(|| KEY.to_string()));
    let state = GatewayState::new(gw, ctx, max_concurrent, Some(counters));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await });
    Fixture {
        base: format!("http://{addr}"),
        hooks,
        counts,
        _dir: dir,
    }
}

fn verify_request(c: &reqwest::Client, f: &Fixture, key: Option<&str>) -> reqwest::RequestBuilder {
    let mut r = c
        .get(format!("{}{}", f.base, VERIFY_PATH))
        .header("x-original-url", "https://app.example.test/a")
        .header("x-forwarded-host", "app.example.test")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "203.0.113.9")
        .header("sec-fetch-dest", "document");
    if let Some(k) = key {
        r = r.header("x-hopae-gateway-key", k);
    }
    r
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn s004_a8_wrong_or_missing_key_touches_no_state() {
    let f = serve(8).await;
    let c = client();
    for key in [None, Some("wrong")] {
        let resp = verify_request(&c, &f, key).send().await.unwrap();
        assert_eq!(resp.status(), 403);
        assert_eq!(resp.headers()["x-hopae-reason"], "caller_unauthorized");
        assert!(resp.headers().get("set-cookie").is_none());
    }
    // A second copy of the right value is refused too.
    let resp = verify_request(&c, &f, Some(KEY))
        .header("x-hopae-gateway-key", KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert!(
        f.hooks.calls().is_empty(),
        "no store call: {:?}",
        f.hooks.calls()
    );
    let counts = f.counts.lock().unwrap();
    let unauthorized = counts
        .iter()
        .filter(|c| c.starts_with("hopae_verify_unauthorized_total"))
        .count();
    assert_eq!(unauthorized, 3);
}

#[tokio::test]
async fn accepted_key_slot_is_counted() {
    let f = serve(8).await;
    let c = client();
    let resp = verify_request(&c, &f, Some(KEY)).send().await.unwrap();
    assert!(!resp.status().is_success());
    assert!(
        f.counts
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "hopae_verify_caller_key_total{key=current}")
    );
}

#[tokio::test]
async fn s004_a3_no_permit_answers_503_overloaded_immediately() {
    let f = serve(0).await;
    let c = client();
    let resp = verify_request(&c, &f, Some(KEY)).send().await.unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["x-hopae-reason"], "overloaded");
    assert_eq!(resp.headers()["retry-after"], "1");
    assert!(
        f.counts
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("hopae_verify_overloaded_total"))
    );
    assert!(f.hooks.calls().is_empty());
}

#[tokio::test]
async fn only_get_on_the_verify_path_is_served() {
    let f = serve(8).await;
    let c = client();
    let post = c
        .post(format!("{}{}", f.base, VERIFY_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 405);
    let other = c.get(format!("{}/healthz", f.base)).send().await.unwrap();
    assert_eq!(other.status(), 404);
}
