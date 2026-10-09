//! The S004-11 walk, callable from the integration tests (`test-hooks`) as
//! well as from the unit tests: no decision other than `Allow` ever renders
//! to a `2xx`.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::Response;

use super::{GatewayConfig, RenderEnv, decision_label, render};
use crate::config::CookieNames;
use crate::crypto::{Secret, Timestamp};
use crate::event::types::reasons;
use crate::identity::types::{NormalizedEmail, UserId};
use crate::provider::types::ProviderId;
use crate::session::types::{Aal, FactorEntry, FactorKind, Generations, SessionId};
use crate::verify::types::*;

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn cfg() -> GatewayConfig {
    GatewayConfig {
        cookies: CookieNames {
            handle: "__Host-hopae".into(),
            bind: "__Host-hopae_bind".into(),
            portal: "__Host-hopae_portal".into(),
        },
        portal_url: url::Url::parse("https://auth.example.test/").expect("literal url"),
        secure: true,
    }
}

fn env() -> RenderEnv {
    RenderEnv {
        request_id: "r_test".into(),
        original_url: url::Url::parse("https://app.example.test/admin/x?q=1&_hopae_handoff=K1")
            .ok(),
        bind_cookie: None,
        handoff_seen: false,
        detail: None,
    }
}

fn identity() -> Identity {
    Identity {
        user_id: UserId::new("u_1"),
        email: NormalizedEmail::parse("a@example.test").ok(),
        preferred_username: Some("alice".into()),
        groups: vec![],
        session_id: SessionId::new("s_1"),
        provider_id: ProviderId::new("mock"),
        auth_time: Timestamp(1_800_000_000_000),
        expires_at: Timestamp(1_800_043_200_000),
        aal: Aal::One,
        factors: vec![FactorEntry {
            kind: FactorKind::Oidc,
            provider: Some(ProviderId::new("mock")),
            at: Timestamp(1_800_000_000_000),
        }],
        generations: Generations {
            session: 2,
            user: 3,
            config: 5,
        },
    }
}

/// S004-11: the exhaustive walk over every decision shape, every reason code
/// and every deny kind, for both navigation kinds: only `Decision::Allow` ever
/// renders to a `2xx`, and no other answer carries the terminal-response marker.
/// Called by the unit test and by the integration test `s004_11_*`.
pub fn assert_only_allow_is_2xx() {
    let url = || url::Url::parse("https://app.example.test/a").expect("literal url");
    let tok = || Secret::new("T".into());
    let mut decisions: Vec<Decision> = vec![
        Decision::Login {
            transaction: Some(tok()),
            bind: BindAction::Plant(tok()),
            kind: LoginKind::Login,
            clear_handle: true,
            cause: Some(reasons::UNKNOWN_HANDLE),
        },
        Decision::Login {
            transaction: Some(tok()),
            bind: BindAction::Keep,
            kind: LoginKind::StepUp,
            clear_handle: false,
            cause: None,
        },
        Decision::Login {
            transaction: None,
            bind: BindAction::Keep,
            kind: LoginKind::Login,
            clear_handle: false,
            cause: None,
        },
        Decision::Handoff {
            location: url(),
            handle: tok(),
            issued_aal: Aal::Two,
            max_age: Duration::from_secs(1),
        },
        Decision::CleanRedirect { location: url() },
        Decision::Switch { transaction: tok() },
    ];
    let kinds = |retry: Duration| {
        [
            DenyKind::Forbidden,
            DenyKind::ForbiddenHtml,
            DenyKind::RateLimited { retry_after: retry },
            DenyKind::ContractViolation,
            DenyKind::Unavailable { retry_after: retry },
        ]
    };
    for reason in reasons::ALL {
        for kind in kinds(Duration::from_secs(30)) {
            decisions.push(Decision::Deny {
                reason: *reason,
                kind,
            });
        }
    }
    decisions.push(Decision::Deny {
        reason: reasons::OK,
        kind: DenyKind::Forbidden,
    });
    for d in decisions {
        for nav in [Navigation::Document, Navigation::Other] {
            let d2 = clone_decision(&d);
            let resp = render(d2, nav, &env(), &cfg());
            let s = resp.status().as_u16();
            assert!(
                matches!(s, 302 | 401 | 403 | 400 | 503),
                "non-allow rendered {s} for {:?}",
                decision_label(&d)
            );
            assert!(resp.headers().get("x-hangang-auth-terminal").is_none());
            assert_eq!(header(&resp, "x-hopae-contract"), Some("1"));
            assert!(header(&resp, "x-hopae-reason").is_some());
            assert!(header(&resp, "x-forwarded-user").is_none());
        }
    }
    let allow = render(
        Decision::Allow {
            identity: identity(),
            cache: Cacheability::NoStore,
        },
        Navigation::Document,
        &env(),
        &cfg(),
    );
    assert_eq!(allow.status(), StatusCode::OK);
}

fn clone_decision(d: &Decision) -> Decision {
    match d {
        Decision::Allow { .. } => unreachable!("allow is rendered separately"),
        Decision::Login {
            transaction,
            bind,
            kind,
            clear_handle,
            cause,
        } => Decision::Login {
            transaction: transaction.clone(),
            bind: match bind {
                BindAction::Keep => BindAction::Keep,
                BindAction::Plant(s) => BindAction::Plant(s.clone()),
            },
            kind: *kind,
            clear_handle: *clear_handle,
            cause: *cause,
        },
        Decision::Handoff {
            location,
            handle,
            issued_aal,
            max_age,
        } => Decision::Handoff {
            location: location.clone(),
            handle: handle.clone(),
            issued_aal: *issued_aal,
            max_age: *max_age,
        },
        Decision::CleanRedirect { location } => Decision::CleanRedirect {
            location: location.clone(),
        },
        Decision::Switch { transaction } => Decision::Switch {
            transaction: transaction.clone(),
        },
        Decision::Deny { reason, kind } => Decision::Deny {
            reason: *reason,
            kind: *kind,
        },
    }
}
