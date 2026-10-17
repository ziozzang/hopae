//! S495: risk-based step-up from the gateway's signed network evidence (ADR-0023).
use super::s004_verify::fx::*;
use crate::support::{Fixture, Hopae, MockIdp, VerifyRequest};
use hopae::event::types::reasons;
use hopae::policy::risk::{Keys, RiskCfg};
use hopae::session::types::{Aal, FactorEntry, FactorKind};
use hopae::verify::{Decision, LoginKind, RiskHeader};
use serde_json::json;
use std::sync::Arc;

const KEY: &str = "risk-context-key-0123456789abcdef-owned-fixture";
const URL: &str = "https://app.example.test/admin/x";

fn claims(level: &str, country: &str, asn: u32, iat: i64) -> serde_json::Value {
    json!({"iat": iat, "level": level, "source": "sumunjang", "mode": "enforce",
           "reason": "sumunjang.asn_reputation", "asn": asn, "country": country, "zones": []})
}

fn rules() -> serde_json::Value {
    json!({"rules": [
        {"path_prefix": "/admin", "when": {"level_at_least": "elevated"}, "then": {"step_up": {"aal": 2, "max_age_secs": 600}}},
        {"when": {"country_changed": true}, "then": {"step_up": {"aal": 2, "max_age_secs": 300}}},
        {"when": {"level_at_least": "high"}, "then": "deny"}
    ]})
}

fn fx(missing: Option<serde_json::Value>) -> Fx {
    let mut f = Fx::with("m1-basic", |v| {
        v["risk"] = json!({"context_key_env": "HOPAE_TEST_RISK_KEY"});
        let mut r = rules();
        if let Some(m) = missing {
            r["missing"] = m;
        }
        v["apps"][0]["risk"] = r;
    });
    let cfg: RiskCfg = serde_json::from_value(json!({"context_key_env": "X"})).unwrap();
    f.ctx.risk_keys = Some(Arc::new(Keys::new(
        vec![KEY.as_bytes().to_vec()],
        cfg.max_skew(),
    )));
    f
}

fn with_context(
    f: &Fx,
    req: Req,
    level: &str,
    country: &str,
    asn: u32,
) -> hopae::verify::VerifyInput {
    let mut input = req.build();
    let value = Keys::sign(
        KEY.as_bytes(),
        &claims(level, country, asn, f.now().secs()),
        input.method.as_str(),
        input.client_ip,
        URL,
    );
    input.risk_context = RiskHeader::Value {
        value: value.into_bytes(),
        original_url: URL.into(),
    };
    input
}

async fn decide(f: &Fx, input: hopae::verify::VerifyInput) -> Decision {
    hopae::verify::decide(&f.ctx, input).await
}

/// A user with an AAL 2 session (TOTP `totp_age` seconds ago) and a handle.
async fn signed_in(f: &Fx, totp_age: i64) -> hopae::crypto::Secret {
    let user = f.user("risk@example.test", None, None).await;
    let session = f
        .session_with(&user, |s| {
            s.aal = Aal::Two;
            s.factors.push(FactorEntry {
                kind: FactorKind::Totp,
                provider: None,
                at: hopae::crypto::Timestamp(T0 - totp_age * 1000),
            });
        })
        .await;
    f.handle_with(&session, "app.example.test", |h| h.issued_aal = Aal::Two)
        .await
}

fn is_step_up(d: &Decision) -> bool {
    matches!(
        d,
        Decision::Login {
            kind: LoginKind::StepUp,
            ..
        }
    ) || matches!(d, Decision::Deny { reason, .. } if *reason == reasons::STEP_UP_REQUIRED)
}

#[tokio::test]
async fn s495_1_an_elevated_context_requires_a_fresh_factor_and_high_is_denied() {
    let f = fx(None);
    let stale = signed_in(&f, 3600).await;
    // Low: allowed with an hour-old factor.
    let low = with_context(&f, f.req(URL).cookie(&stale).other(), "low", "KR", 64500);
    assert!(matches!(decide(&f, low).await, Decision::Allow { .. }));
    // Elevated on /admin: the factor must be fresh within 600 s.
    let elevated = with_context(
        &f,
        f.req(URL).cookie(&stale).other(),
        "elevated",
        "KR",
        64500,
    );
    let d = decide(&f, elevated).await;
    assert!(is_step_up(&d));
    // High: denied, before and after authentication.
    let high = with_context(&f, f.req(URL).cookie(&stale).other(), "high", "KR", 64500);
    assert!(
        matches!(decide(&f, high).await, Decision::Deny { reason, .. } if reason == reasons::RISK_DENIED)
    );
    let anonymous = with_context(&f, f.req(URL).other(), "high", "KR", 64500);
    assert!(
        matches!(decide(&f, anonymous).await, Decision::Deny { reason, .. } if reason == reasons::RISK_DENIED)
    );
    // A fresh factor satisfies the elevated rule.
    let f2 = fx(None);
    let fresh = signed_in(&f2, 10).await;
    let elevated = with_context(
        &f2,
        f2.req(URL).cookie(&fresh).other(),
        "elevated",
        "KR",
        64500,
    );
    assert!(matches!(
        decide(&f2, elevated).await,
        Decision::Allow { .. }
    ));
    assert!(
        hopae::telemetry::counters::get(
            hopae::policy::risk::DECISIONS_TOTAL,
            &[("app", "app"), ("level", "elevated"), ("action", "step_up")]
        ) >= 1
    );
}

#[tokio::test]
async fn s495_2_a_change_of_country_within_the_session_steps_up_once() {
    let f = fx(None);
    let h = signed_in(&f, 3600).await;
    let public = "https://app.example.test/public";
    let at = |country: &str| {
        let mut input = f.req(public).cookie(&h).other().build();
        let value = Keys::sign(
            KEY.as_bytes(),
            &claims("low", country, 64500, f.now().secs()),
            "GET",
            input.client_ip,
            public,
        );
        input.risk_context = RiskHeader::Value {
            value: value.into_bytes(),
            original_url: public.into(),
        };
        input
    };
    assert!(
        matches!(decide(&f, at("KR")).await, Decision::Allow { .. }),
        "remembers KR"
    );
    assert!(matches!(decide(&f, at("KR")).await, Decision::Allow { .. }));
    let moved = decide(&f, at("JP")).await;
    assert!(is_step_up(&moved));
    // The step-up did not record JP: back in KR the session is unchanged.
    assert!(matches!(decide(&f, at("KR")).await, Decision::Allow { .. }));
    // A session with a fresh factor moves to JP; JP is remembered then.
    let f2 = fx(None);
    let fresh = signed_in(&f2, 10).await;
    let mk = |country: &str| {
        let mut input = f2.req(public).cookie(&fresh).other().build();
        let value = Keys::sign(
            KEY.as_bytes(),
            &claims("low", country, 64500, f2.now().secs()),
            "GET",
            input.client_ip,
            public,
        );
        input.risk_context = RiskHeader::Value {
            value: value.into_bytes(),
            original_url: public.into(),
        };
        input
    };
    assert!(matches!(
        decide(&f2, mk("KR")).await,
        Decision::Allow { .. }
    ));
    assert!(
        matches!(decide(&f2, mk("JP")).await, Decision::Allow { .. }),
        "fresh factor satisfies"
    );
    assert!(matches!(
        decide(&f2, mk("JP")).await,
        Decision::Allow { .. }
    ));
}

#[tokio::test]
async fn s495_3_forged_stale_moved_and_duplicate_contexts_are_refused() {
    let f = fx(None);
    let h = signed_in(&f, 10).await;
    let refused = |d: Decision| matches!(d, Decision::Deny { reason, .. } if reason == reasons::RISK_CONTEXT_INVALID);
    // Another key.
    let mut input = f.req(URL).cookie(&h).other().build();
    let value = Keys::sign(
        b"a-client-chosen-key-of-at-least-32-bytes",
        &claims("low", "KR", 1, f.now().secs()),
        "GET",
        input.client_ip,
        URL,
    );
    input.risk_context = RiskHeader::Value {
        value: value.into_bytes(),
        original_url: URL.into(),
    };
    assert!(refused(decide(&f, input).await));
    // Stale.
    let mut input = f.req(URL).cookie(&h).other().build();
    let value = Keys::sign(
        KEY.as_bytes(),
        &claims("low", "KR", 1, f.now().secs() - 120),
        "GET",
        input.client_ip,
        URL,
    );
    input.risk_context = RiskHeader::Value {
        value: value.into_bytes(),
        original_url: URL.into(),
    };
    assert!(refused(decide(&f, input).await));
    // Signed for another client address.
    let mut input = f.req(URL).cookie(&h).other().build();
    let value = Keys::sign(
        KEY.as_bytes(),
        &claims("low", "KR", 1, f.now().secs()),
        "GET",
        "198.51.100.1".parse().unwrap(),
        URL,
    );
    input.risk_context = RiskHeader::Value {
        value: value.into_bytes(),
        original_url: URL.into(),
    };
    assert!(refused(decide(&f, input).await));
    // Plain values a client could type.
    let mut input = f.req(URL).cookie(&h).other().build();
    input.risk_context = RiskHeader::Value {
        value: b"level=low".to_vec(),
        original_url: URL.into(),
    };
    assert!(refused(decide(&f, input).await));
    let mut input = f.req(URL).cookie(&h).other().build();
    input.risk_context = RiskHeader::Duplicate;
    assert!(refused(decide(&f, input).await));
}

#[tokio::test]
async fn s495_4_a_missing_context_follows_the_application() {
    let h_ignore = fx(None);
    let h = signed_in(&h_ignore, 3600).await;
    assert!(matches!(
        h_ignore.decide(h_ignore.req(URL).cookie(&h).other()).await,
        Decision::Allow { .. }
    ));
    let f = fx(Some(json!("deny")));
    let h = signed_in(&f, 3600).await;
    assert!(
        matches!(f.decide(f.req(URL).cookie(&h).other()).await, Decision::Deny { reason, .. } if reason == reasons::RISK_CONTEXT_MISSING)
    );
    let f = fx(Some(json!({"step_up": {"aal": 2, "max_age_secs": 300}})));
    let h = signed_in(&f, 3600).await;
    assert!(is_step_up(&f.decide(f.req(URL).cookie(&h).other()).await));
}

/// Through the real gateway listener: the header is read from the verify
/// request, verified with the key from the environment and bound to it.
#[test]
fn s495_5_the_gateway_refuses_spoofed_and_accepts_signed_contexts() {
    let idp = MockIdp::start("default");
    let h = Hopae::spawn(
        Fixture::with(
            "m1-basic",
            json!({"risk": {"context_key_env": "HOPAE_TEST_RISK_KEY"}, "apps": [{"app_id": "app", "risk": rules()}]}),
        ),
        &idp,
        &[("HOPAE_TEST_RISK_KEY", KEY)],
    );
    let now = h.hooks.now_ms() / 1000;
    let signed = |level: &str, ip: &str| {
        Keys::sign(
            KEY.as_bytes(),
            &claims(level, "KR", 64500, now),
            "GET",
            ip.parse().unwrap(),
            URL,
        )
    };
    // No context: the default `missing` ignores it, a sign-in starts.
    let r = h.verify(VerifyRequest::document(URL));
    assert_eq!(r.status, 302, "{r:?}");
    // A client-typed value, and one signed with another key: refused.
    for spoof in ["v1.eyJsZXZlbCI6ImxvdyJ9.AAAA", "level=low"] {
        let r = h.verify(VerifyRequest::document(URL).header("x-hopae-risk-context", spoof));
        assert_eq!(
            (r.status, r.header("x-hopae-reason")),
            (403, Some("risk_context_invalid")),
            "{spoof}"
        );
    }
    let other = Keys::sign(
        b"another-key-of-at-least-thirty-two-bytes",
        &claims("low", "KR", 1, now),
        "GET",
        "192.0.2.10".parse().unwrap(),
        URL,
    );
    let r = h.verify(VerifyRequest::document(URL).header("x-hopae-risk-context", &other));
    assert_eq!(r.status, 403);
    // A valid context signed for another client: refused (bound to the request).
    let r = h.verify(
        VerifyRequest::document(URL).header("x-hopae-risk-context", &signed("low", "198.51.100.1")),
    );
    assert_eq!(r.header("x-hopae-reason"), Some("risk_context_invalid"));
    // Two headers: refused.
    let v = signed("low", "192.0.2.10");
    let r = h.verify(
        VerifyRequest::document(URL)
            .header("x-hopae-risk-context", &v)
            .header("x-hopae-risk-context", &v),
    );
    assert_eq!(r.header("x-hopae-reason"), Some("risk_context_invalid"));
    // Signed: low starts a sign-in, high is denied.
    let r = h.verify(
        VerifyRequest::document(URL).header("x-hopae-risk-context", &signed("low", "192.0.2.10")),
    );
    assert_eq!(r.status, 302, "{r:?}");
    let r = h.verify(
        VerifyRequest::document(URL).header("x-hopae-risk-context", &signed("high", "192.0.2.10")),
    );
    assert_eq!(
        (r.status, r.header("x-hopae-reason")),
        (403, Some("risk_denied"))
    );
}

#[test]
fn s495_a1_risk_configuration_is_checked() {
    let idp = MockIdp::start("default");
    let dir = tempfile::tempdir().unwrap();
    for (over, key) in [
        (json!({"apps": [{"app_id": "app", "risk": rules()}]}), KEY),
        (
            json!({"risk": {"context_key_env": "K"}, "apps": [{"app_id": "app", "risk": {"rules": [{"when": {}, "then": "deny"}]}}]}),
            KEY,
        ),
        (
            json!({"risk": {"context_key_env": "K", "max_skew_secs": 1}}),
            KEY,
        ),
        (json!({"risk": {"context_key_env": "K"}}), "short"),
        (
            json!({"risk": {"context_key_env": "K"}, "apps": [{"app_id": "app", "risk": {"rules": [{"when": {"level_at_least": "high"}, "then": {"step_up": {"aal": 2}}}]}}]}),
            KEY,
        ),
    ] {
        let cfg = Fixture::with("m1-basic", over.clone()).render(dir.path(), &idp);
        let path = crate::support::write_config(dir.path(), &cfg.to_string());
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hopae"))
            .args(["--check", "--config"])
            .arg(&path)
            .env("K", key)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{over}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// explain/authentication takes a hypothetical context and memory and shows
/// the risk inputs, the matched rules and the action.
#[test]
fn s495_6_explain_shows_risk_inputs_and_decisions() {
    use super::s301_admin_users::kit::Who;
    use super::s307_subject_directory::dkit;
    let mut apps = dkit::overrides()["apps"].clone();
    apps[0]["risk"] = rules();
    let k = dkit::console(
        json!({"risk": {"context_key_env": "HOPAE_TEST_RISK_KEY"}, "apps": apps}),
        &[("HOPAE_TEST_RISK_KEY", KEY)],
    );
    let a: Who = k.admin("ha495", hopae::store::types::AdminRole::Admin);
    k.add_user("u_r", "r@example.test", "Ria");
    k.add_identity("u_r", "mock", "sub-r", "r@example.test");
    let explain = |body: serde_json::Value| {
        let r = k.client(&a).post_json("/v1/explain/authentication", body);
        assert_eq!(r.status, 200, "{r:?}");
        r.json()
    };
    let ctx = |level: &str, country: &str| json!({"iat": 0, "level": level, "source": "sumunjang", "mode": "observe", "reason": "sumunjang.geo", "country": country, "asn": 64500});
    // High: denied by rule 2.
    let e = explain(
        json!({"url": "https://app.example.test/public", "subject": "u_r",
        "hypothetical": {"aal": 2, "factors": ["totp"]}, "risk": {"context": ctx("high", "KR")}}),
    );
    assert_eq!(e["after_login"]["outcome"], "deny", "{e}");
    assert_eq!(e["after_login"]["reason"]["code"], "hopae.risk_denied");
    // Another country than the session's: rule 1 adds a 300 s step-up.
    let e = explain(
        json!({"url": "https://app.example.test/public", "subject": "u_r",
        "hypothetical": {"aal": 2, "factors": ["totp"], "auth_age_seconds": 900},
        "risk": {"context": ctx("low", "JP"), "session_country": "KR", "user_countries": ["KR"]}}),
    );
    let risk = &e["after_login"]["step_up"]["risk"];
    assert_eq!(risk["matched_rules"], json!([1]), "{e}");
    assert_eq!(risk["action"], "step_up");
    assert_eq!(risk["context"]["country"], "JP");
    assert_eq!(risk["memory"]["session_country"], "KR");
    assert_eq!(
        e["after_login"]["step_up"]["verdict"]["required"]["max_age_seconds"],
        300
    );
    // No context and the default `missing`: nothing matches.
    let e = explain(
        json!({"url": "https://app.example.test/public", "subject": "u_r",
        "hypothetical": {"aal": 2, "factors": ["totp"]}}),
    );
    assert_eq!(e["after_login"]["step_up"]["risk"]["missing"], true);
    assert_eq!(e["after_login"]["outcome"], "allow");
}
