use super::*;
use serde_json::json;

const K1: &[u8] = b"risk-context-key-0123456789abcdef-current";
const K2: &[u8] = b"risk-context-key-0123456789abcdef-next----";
const URL: &str = "https://app.example.test/admin/x";
const NOW: i64 = 1_800_000_000;

fn ip() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}

fn claims() -> serde_json::Value {
    json!({"iat": NOW, "level": "elevated", "source": "sumunjang", "mode": "enforce",
           "reason": "sumunjang.asn_reputation", "score": 70, "asn": 64500, "country": "KR",
           "zones": ["corp-vpn"], "rev": 418})
}

fn keys() -> Keys {
    Keys::new(vec![K1.to_vec(), K2.to_vec()], Duration::from_secs(30))
}

fn at(s: i64) -> Timestamp {
    Timestamp::from_secs(s)
}

#[test]
fn contexts_are_signed_bound_to_the_request_and_fresh() {
    let k = keys();
    let v = Keys::sign(K1, &claims(), "GET", ip(), URL);
    let c = k.verify(v.as_bytes(), "GET", ip(), URL, at(NOW)).unwrap();
    assert_eq!(
        (c.level, c.asn, c.country.as_deref()),
        (Level::Elevated, Some(64500), Some("KR"))
    );
    // The next key is accepted during a rotation; another key is not.
    let next = Keys::sign(K2, &claims(), "GET", ip(), URL);
    assert!(k.verify(next.as_bytes(), "GET", ip(), URL, at(NOW)).is_ok());
    let other = Keys::sign(
        b"another-key-of-at-least-thirty-two-bytes",
        &claims(),
        "GET",
        ip(),
        URL,
    );
    assert_eq!(
        k.verify(other.as_bytes(), "GET", ip(), URL, at(NOW)),
        Err("signature")
    );
    // Moved to another request: method, client, URL.
    assert_eq!(
        k.verify(v.as_bytes(), "POST", ip(), URL, at(NOW)),
        Err("signature")
    );
    assert_eq!(
        k.verify(
            v.as_bytes(),
            "GET",
            "192.0.2.11".parse().unwrap(),
            URL,
            at(NOW)
        ),
        Err("signature")
    );
    assert_eq!(
        k.verify(
            v.as_bytes(),
            "GET",
            ip(),
            "https://app.example.test/other",
            at(NOW)
        ),
        Err("signature")
    );
    // Stale or from the future beyond the skew.
    assert_eq!(
        k.verify(v.as_bytes(), "GET", ip(), URL, at(NOW + 31)),
        Err("stale")
    );
    assert_eq!(
        k.verify(v.as_bytes(), "GET", ip(), URL, at(NOW - 31)),
        Err("stale")
    );
    // A changed payload, an unknown claim, an invalid value, oversized, garbage.
    let tampered = v.replacen("v1.", "v1.e", 1);
    assert!(
        k.verify(tampered.as_bytes(), "GET", ip(), URL, at(NOW))
            .is_err()
    );
    let mut extra = claims();
    extra["level"] = json!("low");
    extra["admin"] = json!(true);
    let extra = Keys::sign(K1, &extra, "GET", ip(), URL);
    assert_eq!(
        k.verify(extra.as_bytes(), "GET", ip(), URL, at(NOW)),
        Err("malformed")
    );
    for bad in [json!("Kr"), json!("KOR")] {
        let mut c = claims();
        c["country"] = bad;
        let s = Keys::sign(K1, &c, "GET", ip(), URL);
        assert_eq!(
            k.verify(s.as_bytes(), "GET", ip(), URL, at(NOW)),
            Err("malformed")
        );
    }
    let mut c = claims();
    c["source"] = json!("client");
    let s = Keys::sign(K1, &c, "GET", ip(), URL);
    assert_eq!(
        k.verify(s.as_bytes(), "GET", ip(), URL, at(NOW)),
        Err("malformed")
    );
    assert_eq!(
        k.verify(&[b'a'; MAX_VALUE + 1], "GET", ip(), URL, at(NOW)),
        Err("oversized")
    );
    assert_eq!(
        k.verify(b"level=high", "GET", ip(), URL, at(NOW)),
        Err("malformed")
    );
}

fn policy(rules: serde_json::Value, missing: Option<serde_json::Value>) -> Policy {
    let mut v = json!({"rules": rules});
    if let Some(m) = missing {
        v["missing"] = m;
    }
    let cfg: AppRiskCfg = serde_json::from_value(v).unwrap();
    let mut errs = Vec::new();
    let p = cfg.compile("apps[0]", false, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    p
}

fn ctx(level: Level, country: &str, asn: u32, zones: &[&str]) -> Input {
    let mut c: Context = serde_json::from_value(claims()).unwrap();
    c.level = level;
    c.country = Some(country.into());
    c.asn = Some(asn);
    c.zones = zones.iter().map(|z| z.to_string()).collect();
    Input::Valid(Box::new(c))
}

#[test]
fn rules_match_levels_zones_and_memory() {
    let p = policy(
        json!([
            {"path_prefix": "/admin", "when": {"level_at_least": "elevated"}, "then": {"step_up": {"aal": 2, "max_age_secs": 600}}},
            {"when": {"country_changed": true}, "then": {"step_up": {"aal": 2, "max_age_secs": 300}}},
            {"when": {"level_at_least": "high"}, "then": "deny"},
            {"when": {"outside_zones": ["corp-vpn"], "country_not_in": ["KR"]}, "then": {"step_up": {"aal": 2, "max_age_secs": 900}}}
        ]),
        None,
    );
    // Low, in the corporate zone, same country: nothing.
    let o = evaluate(
        &p,
        &ctx(Level::Low, "KR", 1, &["corp-vpn"]),
        "/admin/x",
        Some(&Seen::default()),
    );
    assert_eq!(
        (o.action.clone(), o.matched.clone()),
        (Action::Ignore, vec![])
    );
    // Elevated: the path rule only on /admin.
    let o = evaluate(
        &p,
        &ctx(Level::Elevated, "KR", 1, &["corp-vpn"]),
        "/admin/x",
        None,
    );
    assert_eq!(o.matched, vec![0]);
    assert_eq!(o.step_up[0].max_age, Some(Duration::from_secs(600)));
    assert!(
        evaluate(
            &p,
            &ctx(Level::Elevated, "KR", 1, &["corp-vpn"]),
            "/public",
            None
        )
        .matched
        .is_empty()
    );
    // High: deny wins over the step-up.
    let o = evaluate(
        &p,
        &ctx(Level::High, "KR", 1, &["corp-vpn"]),
        "/admin/x",
        None,
    );
    assert_eq!((o.action, o.deciding), (Action::Deny, Some(2)));
    // A change of country within the session, only with the memory.
    let seen = Seen {
        session_country: Some("KR".into()),
        session_asn: Some(1),
        user_countries: vec!["KR".into()],
    };
    let moved = ctx(Level::Low, "JP", 1, &["corp-vpn"]);
    assert_eq!(evaluate(&p, &moved, "/", Some(&seen)).matched, vec![1]);
    assert!(
        evaluate(&p, &moved, "/", None).matched.is_empty(),
        "session rules wait for the session"
    );
    // Outside the corporate zones and abroad.
    let abroad = ctx(Level::Low, "US", 2, &[]);
    assert_eq!(
        evaluate(&p, &abroad, "/", Some(&Seen::default())).matched,
        vec![3]
    );
}

#[test]
fn a_missing_context_follows_the_missing_action() {
    let p = policy(
        json!([{"when": {"level_at_least": "high"}, "then": "deny"}]),
        Some(json!({"step_up": {"aal": 2, "max_age_secs": 300}})),
    );
    let o = evaluate(&p, &Input::Absent, "/", None);
    assert!(o.missing && matches!(o.action, Action::StepUp { .. }) && o.step_up.len() == 1);
    let p = policy(
        json!([{"when": {"level_at_least": "high"}, "then": "deny"}]),
        Some(json!("deny")),
    );
    assert_eq!(evaluate(&p, &Input::Absent, "/", None).action, Action::Deny);
    let p = policy(
        json!([{"when": {"level_at_least": "high"}, "then": "deny"}]),
        None,
    );
    assert_eq!(
        evaluate(&p, &Input::Absent, "/", None).action,
        Action::Ignore
    );
}

#[test]
fn policies_are_validated() {
    for (rules, missing) in [
        (json!([{"when": {}, "then": "deny"}]), None),
        (
            json!([{"when": {"level_at_least": "high"}, "then": "maybe"}]),
            None,
        ),
        (
            json!([{"when": {"level_at_least": "high"}, "then": {"step_up": {"aal": 2, "max_age_secs": 5}}}]),
            None,
        ),
        (
            json!([{"when": {"level_at_least": "high"}, "then": {"step_up": {"aal": 1, "max_age_secs": 60}}}]),
            None,
        ),
        (
            json!([{"when": {"level_at_least": "high"}, "then": {"step_up": {"aal": 3, "max_age_secs": 60}}}]),
            None,
        ),
        (
            json!([{"when": {"country_in": ["kr"]}, "then": "deny"}]),
            None,
        ),
        (json!([{"when": {"zone_in": []}, "then": "deny"}]), None),
        (
            json!([{"path_prefix": "admin", "when": {"level_at_least": "high"}, "then": "deny"}]),
            None,
        ),
        (json!([]), Some(json!("sometimes"))),
    ] {
        let mut v = json!({"rules": rules});
        if let Some(m) = missing {
            v["missing"] = m;
        }
        let cfg: AppRiskCfg = serde_json::from_value(v.clone()).unwrap();
        let mut errs = Vec::new();
        cfg.compile("apps[0]", false, &mut errs);
        assert!(!errs.is_empty(), "{v}");
    }
}

#[test]
fn the_memory_is_bounded_coarse_and_expires() {
    let m = Memory::new(MemoryBounds {
        max_sessions: 2,
        session_ttl: Duration::from_secs(60),
        max_users: 2,
        user_ttl: Duration::from_secs(3600),
        countries_per_user: 2,
    });
    let c = |country: &str, asn: u32| -> Context {
        let mut c: Context = serde_json::from_value(claims()).unwrap();
        c.country = Some(country.into());
        c.asn = Some(asn);
        c
    };
    m.observe("s1", "u1", &c("KR", 1), at(NOW));
    let seen = m.seen("s1", "u1", at(NOW + 1));
    assert_eq!(
        (seen.session_country.as_deref(), seen.session_asn),
        (Some("KR"), Some(1))
    );
    // The session entry expires; the user's countries stay longer.
    let later = m.seen("s1", "u1", at(NOW + 61));
    assert_eq!(later.session_country, None);
    assert_eq!(later.user_countries, ["KR"]);
    // Per user, the most recent countries only; "XX" is never remembered.
    m.observe("s1", "u1", &c("JP", 2), at(NOW + 2));
    m.observe("s1", "u1", &c("US", 3), at(NOW + 3));
    m.observe("s1", "u1", &c("XX", 4), at(NOW + 4));
    assert_eq!(m.seen("s1", "u1", at(NOW + 5)).user_countries, ["JP", "US"]);
    assert_eq!(
        m.seen("s1", "u1", at(NOW + 5)).session_country,
        None,
        "XX clears the session country"
    );
    // At most two sessions: the oldest goes.
    m.observe("s2", "u2", &c("KR", 1), at(NOW + 6));
    m.observe("s3", "u3", &c("KR", 1), at(NOW + 7));
    assert_eq!(m.seen("s1", "u1", at(NOW + 8)).session_asn, None);
    assert_eq!(m.seen("s3", "u3", at(NOW + 8)).session_asn, Some(1));
    assert!(
        m.seen("s1", "u1", at(NOW + 8)).user_countries.is_empty(),
        "u1 evicted by u2 and u3"
    );
}

/// The documented test vector (GATEWAY_CONTRACT.md "Risk context"), produced
/// by an independent implementation (Python hmac).
#[test]
fn the_documented_vector_verifies() {
    let k = Keys::new(vec![K1.to_vec()], Duration::from_secs(30));
    let v = "v1.eyJpYXQiOjE4MDAwMDAwMDAsImxldmVsIjoiZWxldmF0ZWQiLCJzb3VyY2UiOiJzdW11bmphbmciLCJtb2RlIjoiZW5mb3JjZSIsInJlYXNvbiI6InN1bXVuamFuZy5hc25fcmVwdXRhdGlvbiIsInNjb3JlIjo3MCwiYXNuIjo2NDUwMCwiY291bnRyeSI6IktSIiwiem9uZXMiOlsiY29ycC12cG4iXSwicmV2Ijo0MTh9.oIlJD45LbUbFg80GNO6g_delXTIQ_7m2lVOgtIPcDZQ";
    let c = k
        .verify(v.as_bytes(), "GET", ip(), URL, at(NOW + 29))
        .unwrap();
    assert_eq!(
        (c.level, c.rev, c.zones.as_slice()),
        (Level::Elevated, Some(418), &["corp-vpn".to_string()][..])
    );
}
