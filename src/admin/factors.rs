//! A user's second factors in the console (ADR-0017, console factor
//! management): `GET /v1/users/{id}/factors` lists the passkeys (authenticator
//! name from the AAGUID, backup state, last use), the authenticator app and the
//! recovery codes left; `POST /v1/users/{id}/factors/reset` removes all of them
//! or one passkey, the authenticator app or the unused recovery codes, ends
//! the sessions the removed factor vouched for and records
//! `admin.factor_reset` in the same transaction.
//!
//! The listing is an audited read (`admin.read`, purpose `users.factors`,
//! rate-limited per actor); the reset is a console mutation (CSRF or the JSON
//! API rule, then the administrator role, then the write fence) with an
//! optional `reason` recorded as the event's note. No credential id, public
//! key, TOTP seed or recovery code ever leaves the store: a passkey is named by
//! its `pk_` factor id.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use super::csrf::Mutation;
use super::reads::{self, Op};
use super::users::common::{self, Fail, deny, fail, reason_of, store_failure, write_failure};
use super::{AdminState, Ctx, api};
use crate::config::valid_user_id;
use crate::event::types::{EventKind, Outcome, reasons};
use crate::identity::types::UserId;
use crate::store::passkeys::{FactorResetScope, FactorSummary, PasskeyRecord};
use crate::store::types::GrantTarget;
use crate::store::{Passkeys, StoreError};
use crate::telemetry::counters;

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` of an AAGUID.
fn aaguid_text(a: &[u8; 16]) -> String {
    webauthn_rs::prelude::Uuid::from_bytes(*a)
        .hyphenated()
        .to_string()
}

fn passkey_json(p: &PasskeyRecord) -> Value {
    // An all-zero AAGUID is "not disclosed" (synced passkeys, `none` attestation).
    let aaguid = p.aaguid.filter(|a| a.iter().any(|b| *b != 0));
    json!({
        "factor_id": crate::store::sqlite::webauthn::factor_id(&p.credential_id),
        "label": p.label,
        "aaguid": aaguid.as_ref().map(aaguid_text),
        "authenticator": aaguid.as_ref().and_then(crate::factor::webauthn::authenticator_name),
        "kind": if p.backup_eligible { "synced" } else { "device_bound" },
        "backup_eligible": p.backup_eligible,
        "backup_state": p.backup_state,
        "user_verified": p.user_verified,
        "attested": p.attested,
        "attestation_format": p.attestation_format,
        "assurance": p.assurance.as_str(),
        "transports": p.transports,
        "created_at": p.created_at.secs(),
        "last_used_at": p.last_used_at.map(|t| t.secs()),
    })
}

fn summary_json(user: &UserId, s: &FactorSummary) -> Value {
    json!({
        "user_id": user.as_str(),
        "second_factors": s.second_factors(),
        "passkeys": s.passkeys.iter().map(passkey_json).collect::<Vec<_>>(),
        "totp": {"active": s.totp_active},
        "recovery_codes": {
            "remaining": s.recovery_unused,
            "generated_at": s.recovery_generated_at.map(|t| t.secs()),
            // A code was used: the user must enroll a new factor.
            "reenrollment_required_at": s.recovery_required_at.map(|t| t.secs()),
        },
    })
}

/// The user, or `404 not_found`; `400 invalid_id` for a malformed id.
async fn existing_user(st: &AdminState, c: &Ctx, id: &str) -> Result<UserId, Fail> {
    if !valid_user_id(id) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
    }
    let uid = UserId::new(id);
    st.directory
        .resolve_grant_target(&GrantTarget::Id(uid.clone()), api::deadline(st))
        .await
        .map_err(|e| store_failure(c, "factors", &e))?
        .map(|_| uid)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "not_found"))
}

/// `GET /v1/users/{id}/factors`.
pub async fn list_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = reads::limit(&st, &c, Op::Factors) {
        return r;
    }
    let run = async {
        let user = existing_user(&st, &c, &id).await?;
        let summary = st
            .profile_store
            .factor_summary(&user)
            .await
            .map_err(|e| store_failure(&c, "factors", &e))?;
        reads::audit(&st, &c, Op::Factors, id.as_bytes(), |b| {
            b.user(&user).attr(
                "count",
                summary.passkeys.len() + usize::from(summary.totp_active),
            )
        })
        .await?;
        let mut r = api::json(StatusCode::OK, &summary_json(&user, &summary));
        r.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        Ok::<_, Fail>(r)
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

/// The reset request: `{"scope": "all"|"passkey"|"totp"|"recovery_codes",
/// "factor_id": "pk_…" (passkey only), "reason": "…"}`.
fn scope_of(body: &[u8]) -> Result<FactorResetScope, Fail> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        scope: String,
        #[serde(default)]
        factor_id: Option<String>,
        // Read by `reason_of`.
        #[serde(default)]
        #[allow(dead_code)]
        reason: Option<Value>,
    }
    let bad = || fail(StatusCode::BAD_REQUEST, "invalid_request");
    let input: Input = serde_json::from_slice(body).map_err(|_| bad())?;
    let pk = |v: &str| {
        v.len() == 19
            && v.starts_with("pk_")
            && v[3..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    match (input.scope.as_str(), input.factor_id) {
        ("all", None) => Ok(FactorResetScope::All),
        ("totp", None) => Ok(FactorResetScope::Totp),
        ("recovery_codes", None) => Ok(FactorResetScope::RecoveryCodes),
        ("passkey", Some(id)) if pk(&id) => Ok(FactorResetScope::Passkey(id)),
        _ => Err(bad()),
    }
}

/// `POST /v1/users/{id}/factors/reset`.
pub async fn reset_api(
    State(st): State<Arc<AdminState>>,
    c: Ctx,
    Path(id): Path<String>,
    Extension(m): Extension<Mutation>,
) -> Response {
    let run = async {
        if !valid_user_id(&id) {
            return Err(fail(StatusCode::BAD_REQUEST, "invalid_id"));
        }
        let scope = scope_of(&m.body)?;
        let reason = reason_of(&m)?;
        let target = UserId::new(&id);
        // Resetting one's own factors from the console would end the
        // console session itself (and could lock the operator out).
        if target == c.principal.user_id {
            return Err(deny(&st, &c, reasons::SELF_TARGET).await);
        }
        let mut ev = common::admin_event(&st, &c, EventKind::AdminFactorReset, Outcome::Success)
            .user(&target)
            .reason(reasons::FACTOR_RESET)
            .attr("scope", scope.as_str());
        if let FactorResetScope::Passkey(f) = &scope {
            ev = ev.attr("factor_id", f.as_str());
        }
        if let Some(r) = &reason {
            ev = ev.attr("note", r.as_str());
        }
        let res = st
            .profile_store
            .admin_reset_factors(
                &api::actor(&c.principal),
                &api::actor_policy(&st, &c.principal),
                &target,
                scope.clone(),
                api::deadline(&st),
                ev.build(),
            )
            .await;
        let (changed, report) = match res {
            Ok(v) => v,
            Err(StoreError::Conflict("unknown factor")) => {
                return Err(fail(StatusCode::NOT_FOUND, "factor_not_found"));
            }
            Err(e) => return Err(write_failure(&st, &c, "factors", &e).await),
        };
        if changed {
            common::count_event(EventKind::AdminFactorReset, Outcome::Success);
            for _ in 0..report.sessions {
                common::count_event(EventKind::SessionTerminated, Outcome::Success);
            }
            counters::inc(counters::ADMIN_MUTATIONS_TOTAL, &[("kind", "factor_reset")]);
        }
        Ok(api::json(
            StatusCode::OK,
            &json!({
                "changed": changed,
                "scope": scope.as_str(),
                "passkeys_revoked": report.passkeys,
                "totp_revoked": report.totp,
                "recovery_codes_removed": report.recovery_codes,
                "sessions_terminated": report.sessions,
            }),
        ))
    };
    run.await.unwrap_or_else(|f| f.respond(&st, &c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_scopes_are_exact() {
        let ok = |b: &str| scope_of(b.as_bytes()).ok();
        assert_eq!(ok(r#"{"scope":"all"}"#), Some(FactorResetScope::All));
        assert_eq!(
            ok(r#"{"scope":"totp","reason":"lost phone"}"#),
            Some(FactorResetScope::Totp)
        );
        assert_eq!(
            ok(r#"{"scope":"recovery_codes"}"#),
            Some(FactorResetScope::RecoveryCodes)
        );
        assert_eq!(
            ok(r#"{"scope":"passkey","factor_id":"pk_0123456789abcdef"}"#),
            Some(FactorResetScope::Passkey("pk_0123456789abcdef".into()))
        );
        for bad in [
            "",
            "{}",
            r#"{"scope":"passkey"}"#,
            r#"{"scope":"passkey","factor_id":"pk_0123"}"#,
            r#"{"scope":"passkey","factor_id":"pk_0123456789ABCDEF"}"#,
            r#"{"scope":"all","factor_id":"pk_0123456789abcdef"}"#,
            r#"{"scope":"everything"}"#,
        ] {
            assert!(ok(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn aaguids_are_hyphenated_lowercase() {
        let a = [
            0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97,
            0x07, 0x2a,
        ];
        assert_eq!(aaguid_text(&a), "ee882879-721c-4913-9775-3dfcce97072a");
    }
}
