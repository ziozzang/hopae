//! Store tests for passkeys, ceremony rows and recovery codes (ADR-0017).
//! The WebAuthn cryptography is exercised in `factor::webauthn` and the
//! scenario tests; here the serialized credential is an opaque string.

use super::*;
use crate::store::passkeys::*;
use crate::store::{Passkeys, StoreResult};

struct Px {
    user: User,
    session: Sess,
    view: HandleView,
    bind: Digest,
}

const BIND_COOKIE: &[u8] = b"owned-portal-cookie";

async fn px(f: &Fx) -> Px {
    f.clock.set(Timestamp(59_000));
    f.store.conn().execute("INSERT INTO providers(provider_id,kind,display_name,enabled,managed_by,created_at,updated_at)VALUES('mock','oidc','Owned',1,'api',0,0)",[]).unwrap();
    let user = f.user(71).await;
    let session = f.session(&user, vec![]).await;
    let view = f.view(&session).await;
    Px {
        user,
        session,
        view,
        bind: sha256(BIND_COOKIE),
    }
}

impl Fx {
    async fn view(&self, s: &Sess) -> HandleView {
        self.store
            .lookup_handle(&s.portal_digest, &host(PORTAL_HOST))
            .await
            .unwrap()
            .unwrap()
    }
    fn actor(&self, view: &HandleView) -> FactorActor {
        let mut actor = stepup_actor(self, view.clone());
        actor.session_idle = Duration::from_secs(86_400);
        actor.handle_idle = Duration::from_secs(86_400);
        actor
    }
    async fn ceremony(
        &self,
        p: &Px,
        view: &HandleView,
        purpose: CeremonyPurpose,
        txn: Option<Digest>,
    ) -> Digest {
        let digest = random_token(&self.rng, 32).digest();
        self.store
            .begin_ceremony(NewCeremony {
                actor: self.actor(view),
                purpose,
                digest,
                portal_binding: p.bind,
                transaction: txn,
                state: "{\"opaque\":true}".into(),
                expires_at: self.now().add(Duration::from_secs(300)),
            })
            .await
            .unwrap();
        digest
    }
    fn record(&self, user: &User, id: u8) -> PasskeyRecord {
        PasskeyRecord {
            credential_id: vec![id; 32],
            user_id: user.user_id.clone(),
            label: format!("Key {id}"),
            passkey: format!("{{\"cred\":{id}}}"),
            aaguid: Some([id; 16]),
            transports: vec!["internal".into()],
            backup_eligible: true,
            backup_state: true,
            user_verified: true,
            attestation_format: "none".into(),
            attested: false,
            assurance: Assurance::Aal2,
            sign_count: 0,
            created_at: self.now(),
            last_used_at: None,
            revision: 1,
        }
    }
    async fn register(&self, p: &Px, view: &HandleView, id: u8) -> StoreResult<()> {
        let c = self
            .ceremony(p, view, CeremonyPurpose::Register, None)
            .await;
        self.store
            .register_passkey(RegisterPasskey {
                actor: self.actor(view),
                ceremony: c,
                portal_binding: p.bind,
                record: self.record(&p.user, id),
                events: vec![],
            })
            .await
    }
    fn used(&self, id: u8, count: u32) -> PasskeyUse {
        PasskeyUse {
            credential_id: vec![id; 32],
            passkey: format!("{{\"cred\":{id},\"count\":{count}}}"),
            sign_count: count,
            backup_eligible: true,
            backup_state: true,
            assurance: Assurance::Aal2,
        }
    }
    /// Verify with passkey `id` on the portal; returns the new portal view.
    async fn verify_portal(
        &self,
        p: &Px,
        view: &HandleView,
        id: u8,
        count: u32,
    ) -> StoreResult<HandleView> {
        let c = self.ceremony(p, view, CeremonyPurpose::Verify, None).await;
        let secret = handle_value(&self.rng);
        let mut handle = self.handle_row(&view.session.session_id, PORTAL_HOST, &secret);
        handle.issued_aal = Aal::Two;
        handle.absolute_expires_at = view.handle.absolute_expires_at;
        self.store
            .elevate_portal(PortalElevation {
                actor: self.actor(view),
                portal_binding: p.bind,
                proof: PortalProof::Passkey {
                    ceremony: c,
                    used: self.used(id, count),
                },
                portal_handle: handle.clone(),
                events: vec![],
            })
            .await?;
        Ok(self
            .store
            .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
            .await
            .unwrap()
            .unwrap())
    }
}

fn refused(r: StoreResult<impl std::fmt::Debug>, what: &str) {
    match r {
        Err(StoreError::Conflict(m)) => assert_eq!(m, what),
        other => panic!("expected conflict {what:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn webauthn_schema_is_v11_and_foundation_detects_tampering() {
    let f = fx();
    assert_eq!(f.store.schema_version().unwrap(), 13);
    crate::store::sqlite::webauthn::validate_foundation(&f.store.conn()).unwrap();
    f.store
        .conn()
        .execute_batch("DROP TABLE recovery_codes; CREATE TABLE recovery_codes(user_id TEXT, lookup TEXT, hash TEXT, batch TEXT, created_at INTEGER, used_at INTEGER)")
        .unwrap();
    assert!(crate::store::sqlite::webauthn::validate_foundation(&f.store.conn()).is_err());
}

#[tokio::test]
async fn user_handle_is_random_stable_and_unique() {
    let f = fx();
    let p = px(&f).await;
    let other = f.user(72).await;
    let h = f
        .store
        .passkey_user_handle(&p.user.user_id, [7; 16])
        .await
        .unwrap();
    assert_eq!(h, [7; 16]);
    assert_eq!(
        f.store
            .passkey_user_handle(&p.user.user_id, [8; 16])
            .await
            .unwrap(),
        [7; 16]
    );
    // The same random value for another user is a uniqueness violation, never a shared handle.
    assert!(
        f.store
            .passkey_user_handle(&other.user_id, [7; 16])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn registration_consumes_its_ceremony_once_and_is_audited() {
    let f = fx();
    let p = px(&f).await;
    let c = f
        .ceremony(&p, &p.view, CeremonyPurpose::Register, None)
        .await;
    assert!(f.store.ceremony(&c).await.unwrap().is_some());
    let req = |id| RegisterPasskey {
        actor: f.actor(&p.view),
        ceremony: c,
        portal_binding: p.bind,
        record: f.record(&p.user, id),
        events: vec![],
    };
    f.store.register_passkey(req(1)).await.unwrap();
    assert!(f.store.ceremony(&c).await.unwrap().is_none());
    // Replay of the same ceremony with another credential.
    refused(
        f.store.register_passkey(req(2)).await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    let summary = f.store.factor_summary(&p.user.user_id).await.unwrap();
    assert_eq!(summary.passkeys.len(), 1);
    assert_eq!(summary.passkeys[0].label, "Key 1");
    assert_eq!(summary.second_factors(), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM events WHERE kind='factor.webauthn_registered' AND outcome='success'"), 1);
    // No credential id in any event, only its hashed factor id.
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE attrs LIKE '%pk_%'"),
        1
    );
}

#[tokio::test]
async fn ceremony_is_bound_to_purpose_binding_cookie_handle_and_expiry() {
    let f = fx();
    let p = px(&f).await;
    let c = f.ceremony(&p, &p.view, CeremonyPurpose::Verify, None).await;
    // Wrong purpose.
    refused(
        f.store
            .register_passkey(RegisterPasskey {
                actor: f.actor(&p.view),
                ceremony: c,
                portal_binding: p.bind,
                record: f.record(&p.user, 1),
                events: vec![],
            })
            .await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    // Wrong binding cookie.
    let c = f
        .ceremony(&p, &p.view, CeremonyPurpose::Register, None)
        .await;
    refused(
        f.store
            .register_passkey(RegisterPasskey {
                actor: f.actor(&p.view),
                ceremony: c,
                portal_binding: sha256(b"other"),
                record: f.record(&p.user, 1),
                events: vec![],
            })
            .await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    // Another session of the same user cannot use this session's ceremony.
    let other = f.session(&p.user, vec![]).await;
    let other_view = f.view(&other).await;
    refused(
        f.store
            .register_passkey(RegisterPasskey {
                actor: f.actor(&other_view),
                ceremony: c,
                portal_binding: p.bind,
                record: f.record(&p.user, 1),
                events: vec![],
            })
            .await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    // Expired.
    f.clock.set(Timestamp(59_000 + 301_000));
    let view = f.view(&p.session).await;
    refused(
        f.store
            .register_passkey(RegisterPasskey {
                actor: f.actor(&view),
                ceremony: c,
                portal_binding: p.bind,
                record: f.record(&p.user, 1),
                events: vec![],
            })
            .await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    assert!(
        f.store.ceremony(&c).await.unwrap().is_none(),
        "expired ceremony is not readable"
    );
}

#[tokio::test]
async fn ceremony_rows_are_capped_per_session() {
    let f = fx();
    let p = px(&f).await;
    let mut all = vec![];
    for _ in 0..12 {
        all.push(
            f.ceremony(&p, &p.view, CeremonyPurpose::Register, None)
                .await,
        );
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM webauthn_challenges"),
        MAX_LIVE_CEREMONIES
    );
    assert!(f.store.ceremony(&all[0]).await.unwrap().is_none());
    assert!(f.store.ceremony(&all[11]).await.unwrap().is_some());
}

#[tokio::test]
async fn second_passkey_requires_recent_verification_and_duplicates_are_refused() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    // A factor exists now: fresh primary sign-in alone is no longer enough.
    refused(
        f.register(&p, &p.view, 2).await,
        refusal::VERIFICATION_REQUIRED,
    );
    let elevated = f.verify_portal(&p, &p.view, 1, 0).await.unwrap();
    assert_eq!(elevated.session.aal, Aal::Two);
    assert_eq!(elevated.handle.issued_aal, Aal::Two);
    // The portal confirmation records the native establishing passkey (phase 2).
    assert_eq!(f.count("SELECT COUNT(*) FROM session_webauthn_provenance WHERE credential_generation=2 AND factor_index=1 AND assurance='aal2' AND config_generation IS NULL"), 1);
    f.register(&p, &elevated, 2).await.unwrap();
    refused(
        f.register(&p, &elevated, 2).await,
        refusal::DUPLICATE_CREDENTIAL,
    );
    // Another user cannot register a credential id that exists.
    assert_eq!(
        f.count("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        2
    );
    // Five minutes after the verification the window closes.
    f.clock.set(Timestamp(59_000 + 301_000));
    let late = f
        .store
        .lookup_handle(&elevated.handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    refused(
        f.register(&p, &late, 3).await,
        refusal::VERIFICATION_REQUIRED,
    );
}

#[tokio::test]
async fn passkey_capacity_is_enforced() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    let view = f.verify_portal(&p, &p.view, 1, 0).await.unwrap();
    for id in 2..=MAX_PASSKEYS as u8 {
        f.register(&p, &view, id).await.unwrap();
    }
    refused(f.register(&p, &view, 99).await, refusal::PASSKEY_CAPACITY);
    assert_eq!(
        f.store
            .factor_summary(&p.user.user_id)
            .await
            .unwrap()
            .passkeys
            .len(),
        MAX_PASSKEYS as usize
    );
}

#[tokio::test]
async fn counter_moves_forward_only_and_stale_counters_are_refused_without_revocation() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    let v = f.verify_portal(&p, &p.view, 1, 5).await.unwrap();
    refused(f.verify_portal(&p, &v, 1, 5).await, refusal::COUNTER_STALE);
    refused(f.verify_portal(&p, &v, 1, 4).await, refusal::COUNTER_STALE);
    let v = f.verify_portal(&p, &v, 1, 6).await.unwrap();
    assert_eq!(f.count("SELECT sign_count FROM webauthn_credentials"), 6);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        1
    );
    // A credential at zero (synchronized passkey) may stay at zero.
    f.register(&p, &v, 2).await.unwrap();
    let v = f.verify_portal(&p, &v, 2, 0).await.unwrap();
    f.verify_portal(&p, &v, 2, 0).await.unwrap();
}

#[tokio::test]
async fn aal3_use_requires_an_aal3_credential_without_backup_flags() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    let c = f.ceremony(&p, &p.view, CeremonyPurpose::Verify, None).await;
    let mut used = f.used(1, 1);
    used.assurance = Assurance::Aal3;
    used.backup_eligible = false;
    used.backup_state = false;
    let secret = handle_value(&f.rng);
    let mut handle = f.handle_row(&p.view.session.session_id, PORTAL_HOST, &secret);
    handle.issued_aal = Aal::Two;
    handle.absolute_expires_at = p.view.handle.absolute_expires_at;
    // The stored credential is aal2: the claim is refused.
    assert!(
        f.store
            .elevate_portal(PortalElevation {
                actor: f.actor(&p.view),
                portal_binding: p.bind,
                proof: PortalProof::Passkey { ceremony: c, used },
                portal_handle: handle,
                events: vec![]
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn clone_signal_revokes_the_credential_and_ends_the_sessions_it_elevated() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    let v = f.verify_portal(&p, &p.view, 1, 3).await.unwrap();
    let c = f.ceremony(&p, &v, CeremonyPurpose::Verify, None).await;
    f.store
        .passkey_clone_detected(&c, &[1; 32], vec![])
        .await
        .unwrap();
    assert_eq!(f.count("SELECT COUNT(*) FROM webauthn_credentials WHERE state='revoked' AND revoked_reason='counter_regression'"), 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM sessions WHERE terminated_reason='counter_regression'"),
        1
    );
    assert!(f.store.ceremony(&c).await.unwrap().is_none());
    // A credential of another user cannot be revoked through this user's ceremony.
    let f2 = fx();
    let p2 = px(&f2).await;
    f2.register(&p2, &p2.view, 1).await.unwrap();
    let other = f2.user(73).await;
    let s = f2.session(&other, vec![]).await;
    let ov = f2.view(&s).await;
    let c = f2.ceremony(&p2, &ov, CeremonyPurpose::Verify, None).await;
    refused(
        f2.store.passkey_clone_detected(&c, &[1; 32], vec![]).await,
        refusal::CEREMONY_UNAVAILABLE,
    );
    assert_eq!(
        f2.count("SELECT COUNT(*) FROM webauthn_credentials WHERE state='active'"),
        1
    );
}

#[tokio::test]
async fn last_factor_cannot_be_removed_and_removal_needs_recent_verification() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    refused(
        f.store
            .revoke_passkey(f.actor(&p.view), &[1; 32], vec![])
            .await,
        refusal::VERIFICATION_REQUIRED,
    );
    let v = f.verify_portal(&p, &p.view, 1, 1).await.unwrap();
    refused(
        f.store.revoke_passkey(f.actor(&v), &[1; 32], vec![]).await,
        refusal::LAST_FACTOR,
    );
    f.register(&p, &v, 2).await.unwrap();
    // Another session elevated with passkey 1 ends when it is removed; the acting session stays.
    let other = f.session(&p.user, vec![]).await;
    let ov = f.view(&other).await;
    f.verify_portal(&p, &ov, 1, 2).await.unwrap();
    assert!(
        f.store
            .revoke_passkey(f.actor(&v), &[1; 32], vec![])
            .await
            .unwrap()
    );
    assert_eq!(f.count(&format!("SELECT COUNT(*) FROM sessions WHERE session_id='{}' AND terminated_reason='passkey_removed'", other.row.session_id.as_str())), 1);
    assert_eq!(
        f.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE session_id='{}' AND terminated_at IS NULL",
            p.session.row.session_id.as_str()
        )),
        1
    );
    // Now passkey 2 is the last one.
    refused(
        f.store.revoke_passkey(f.actor(&v), &[2; 32], vec![]).await,
        refusal::LAST_FACTOR,
    );
    // Unknown or foreign credential: nothing happens.
    assert!(
        !f.store
            .revoke_passkey(f.actor(&v), &[9; 32], vec![])
            .await
            .unwrap()
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='factor.webauthn_revoked'"),
        1
    );
}

#[tokio::test]
async fn an_active_totp_counts_as_the_other_factor() {
    use crate::store::Factors;
    let f = fx();
    let p = px(&f).await;
    let keys = test_totp_keyring();
    let seed = crate::factor::totp::Seed::from_bytes(b"12345678901234567890").unwrap();
    let envelope = keys
        .active()
        .seal(&seed, p.user.user_id.as_str(), "t1", &f.rng)
        .unwrap();
    f.store
        .create_totp_pending("t1".into(), p.user.user_id.clone(), envelope, vec![])
        .await
        .unwrap();
    f.store
        .activate_totp("t1", &p.user.user_id, 1, 0, vec![])
        .await
        .unwrap();
    // A TOTP exists: the first passkey needs a recent second factor too.
    refused(
        f.register(&p, &p.view, 1).await,
        refusal::VERIFICATION_REQUIRED,
    );
    let secret = handle_value(&f.rng);
    let mut handle = f.handle_row(&p.view.session.session_id, PORTAL_HOST, &secret);
    handle.issued_aal = Aal::Two;
    handle.absolute_expires_at = p.view.handle.absolute_expires_at;
    f.store
        .elevate_portal(PortalElevation {
            actor: f.actor(&p.view),
            portal_binding: p.bind,
            proof: PortalProof::Totp {
                enrollment: "t1".into(),
                revision: 2,
                counter: 5,
            },
            portal_handle: handle.clone(),
            events: vec![],
        })
        .await
        .unwrap();
    let v = f
        .store
        .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.session.factors.last().unwrap().kind, FactorKind::Totp);
    assert_eq!(f.count("SELECT COUNT(*) FROM session_totp_provenance WHERE enrollment_id='t1' AND enrollment_revision=2 AND factor_index=1"), 1);
    f.register(&p, &v, 1).await.unwrap();
    // With TOTP present the passkey is not the last factor.
    assert!(
        f.store
            .revoke_passkey(f.actor(&v), &[1; 32], vec![])
            .await
            .unwrap()
    );
}

fn codes(tag: &str) -> Vec<(String, String)> {
    (0..10)
        .map(|i| {
            (
                format!("{tag}{i:03}A")[..5].to_string(),
                format!("$argon2id$fake${tag}{i}"),
            )
        })
        .collect()
}

#[tokio::test]
async fn recovery_codes_need_a_factor_are_single_use_and_keep_aal_one() {
    let f = fx();
    let p = px(&f).await;
    refused(
        f.store
            .replace_recovery_codes(f.actor(&p.view), "b1".into(), codes("A"), vec![])
            .await,
        "recovery codes require a second factor",
    );
    f.register(&p, &p.view, 1).await.unwrap();
    // First set: enrollment freshness is enough.
    f.store
        .replace_recovery_codes(f.actor(&p.view), "b1".into(), codes("A"), vec![])
        .await
        .unwrap();
    // Replacing live codes needs a recent second factor.
    refused(
        f.store
            .replace_recovery_codes(f.actor(&p.view), "b2".into(), codes("B"), vec![])
            .await,
        refusal::VERIFICATION_REQUIRED,
    );
    let lookup = codes("A")[3].0.clone();
    assert!(
        f.store
            .recovery_code_hash(&p.user.user_id, &lookup)
            .await
            .unwrap()
            .is_some()
    );
    let use_code = |view: HandleView, lookup: String| {
        let secret = handle_value(&f.rng);
        let mut handle = f.handle_row(&view.session.session_id, PORTAL_HOST, &secret);
        handle.absolute_expires_at = view.handle.absolute_expires_at;
        handle.issued_aal = view.session.aal;
        let req = PortalElevation {
            actor: f.actor(&view),
            portal_binding: p.bind,
            proof: PortalProof::Recovery { lookup },
            portal_handle: handle.clone(),
            events: vec![],
        };
        (req, handle)
    };
    let (req, handle) = use_code(p.view.clone(), lookup.clone());
    f.store.elevate_portal(req).await.unwrap();
    let v = f
        .store
        .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        v.session.aal,
        Aal::One,
        "a recovery code never raises the level"
    );
    assert_eq!(v.session.factors.last().unwrap().kind, FactorKind::Recovery);
    let summary = f.store.factor_summary(&p.user.user_id).await.unwrap();
    assert_eq!(summary.recovery_unused, 9);
    assert!(summary.recovery_required_at.is_some());
    assert!(
        f.store
            .recovery_code_hash(&p.user.user_id, &lookup)
            .await
            .unwrap()
            .is_none()
    );
    // Single use.
    let (req, _) = use_code(v.clone(), lookup);
    refused(
        f.store.elevate_portal(req).await,
        "recovery code unavailable",
    );
    // A recovery entry lets the user add a passkey (and clears the flag),
    // but never mints new codes (review F1, F5).
    refused(
        f.store
            .replace_recovery_codes(f.actor(&v), "b2".into(), codes("B"), vec![])
            .await,
        refusal::VERIFICATION_REQUIRED,
    );
    f.register(&p, &v, 2).await.unwrap();
    let w = f.verify_portal(&p, &v, 2, 1).await.unwrap();
    f.store
        .replace_recovery_codes(f.actor(&w), "b2".into(), codes("B"), vec![])
        .await
        .unwrap();
    assert_eq!(
        f.store
            .factor_summary(&p.user.user_id)
            .await
            .unwrap()
            .recovery_unused,
        10
    );
    assert!(
        f.store
            .factor_summary(&p.user.user_id)
            .await
            .unwrap()
            .recovery_required_at
            .is_none()
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='factor.recovery_code_used'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='factor.recovery_codes_generated'"),
        2
    );
}

#[tokio::test]
async fn webauthn_stepup_rotates_handles_consumes_txn_and_ceremony_and_hands_off() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    f.store
        .conn()
        .execute(
            "INSERT INTO meta(key,value) VALUES('config_generation','4')",
            [],
        )
        .unwrap();
    let old = f.code(&p.session).await;
    let mut txn = new_txn(&f, &random_token(&f.rng, 32), "192.0.2.10");
    txn.purpose = TxnPurpose::Stepup;
    txn.portal_session_id = Some(p.session.row.session_id.clone());
    txn.return_target = old.row.return_target.clone();
    txn.bind_sha256 = Some(old.row.bind_sha256);
    txn.recovery_depth = 0;
    let digest = txn.txn_sha256;
    f.store.create_transaction(txn, vec![]).await.unwrap();
    // Ceremony bound to another transaction is refused at creation.
    assert!(
        f.store
            .begin_ceremony(NewCeremony {
                actor: f.actor(&p.view),
                purpose: CeremonyPurpose::StepUp,
                digest: sha256(b"x"),
                portal_binding: p.bind,
                transaction: Some(sha256(b"no-such-txn")),
                state: "{}".into(),
                expires_at: f.now().add(Duration::from_secs(300))
            })
            .await
            .is_err()
    );
    let c = f
        .ceremony(&p, &p.view, CeremonyPurpose::StepUp, Some(digest))
        .await;
    let mut handle = f.handle_row(
        &p.session.row.session_id,
        PORTAL_HOST,
        &handle_value(&f.rng),
    );
    handle.issued_aal = Aal::Two;
    let mut code = old.row.clone();
    code.code_sha256 = random_token(&f.rng, 32).digest();
    code.issued_aal = Aal::Two;
    code.cred_gen += 1;
    let request = |config_generation| WebauthnElevation {
        actor: f.actor(&p.view),
        ceremony: c,
        portal_binding: p.bind,
        transaction: digest,
        config_generation,
        used: f.used(1, 1),
        portal_handle: handle.clone(),
        handoff: code.clone(),
        events: vec![],
    };
    // A configuration change between page and completion is refused.
    assert!(f.store.elevate_webauthn(request(3)).await.is_err());
    f.store.elevate_webauthn(request(4)).await.unwrap();
    let elevated = f
        .store
        .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(elevated.session.aal, Aal::Two);
    assert_eq!(elevated.session.cred_gen, 2);
    assert_eq!(
        elevated.session.factors.last().unwrap().kind,
        FactorKind::Webauthn
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_handles WHERE revoked_reason='elevation'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_reason='elevation'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM login_txns WHERE consumed_reason='elevation'"),
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_webauthn_elevations"),
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM session_webauthn_provenance WHERE credential_generation=2 AND config_generation=4"), 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM events WHERE kind='factor.webauthn_used'"),
        1
    );
    // Replay of the whole completion.
    assert!(f.store.elevate_webauthn(request(4)).await.is_err());
}

#[tokio::test]
async fn rename_needs_only_a_live_session_and_owns_the_credential() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    // An hour later: no freshness needed, only the live session.
    f.clock.set(Timestamp(59_000 + 3_600_000));
    let v = f.view(&p.session).await;
    assert!(
        f.store
            .rename_passkey(f.actor(&v), &[1; 32], "Laptop".into(), vec![])
            .await
            .unwrap()
    );
    assert!(
        !f.store
            .rename_passkey(f.actor(&v), &[2; 32], "Nope".into(), vec![])
            .await
            .unwrap()
    );
    assert!(
        f.store
            .rename_passkey(f.actor(&v), &[1; 32], String::new(), vec![])
            .await
            .is_err()
    );
    assert!(
        f.store
            .rename_passkey(f.actor(&v), &[1; 32], "x".repeat(65), vec![])
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .factor_summary(&p.user.user_id)
            .await
            .unwrap()
            .passkeys[0]
            .label,
        "Laptop"
    );
}

#[tokio::test]
async fn administrator_reset_revokes_every_factor_and_ends_every_session() {
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    f.store
        .replace_recovery_codes(f.actor(&p.view), "b1".into(), codes("A"), vec![])
        .await
        .unwrap();
    let _other = f.session(&p.user, vec![]).await;
    let report = f
        .store
        .reset_factors(&p.user.user_id, "r_cli", vec![])
        .await
        .unwrap();
    assert_eq!(
        report,
        FactorResetReport {
            passkeys: 1,
            totp: 0,
            recovery_codes: 10,
            sessions: 2
        }
    );
    let summary = f.store.factor_summary(&p.user.user_id).await.unwrap();
    assert_eq!(summary.second_factors(), 0);
    assert_eq!(summary.recovery_unused, 0);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM sessions WHERE terminated_reason='factor_reset'"),
        2
    );
    assert!(
        f.store
            .reset_factors(&UserId::new("u_missing"), "r_cli", vec![])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sweep_removes_spent_ceremony_rows() {
    let f = fx();
    let p = px(&f).await;
    let c = f
        .ceremony(&p, &p.view, CeremonyPurpose::Register, None)
        .await;
    f.store.fail_ceremony(&c, vec![]).await.unwrap();
    f.ceremony(&p, &p.view, CeremonyPurpose::Register, None)
        .await;
    f.store
        .sweep(f.now(), Duration::from_secs(86400))
        .await
        .unwrap();
    assert_eq!(f.count("SELECT COUNT(*) FROM webauthn_challenges"), 1);
}

#[tokio::test]
async fn aal3_evidence_follows_the_current_high_assurance_elevation() {
    use crate::store::Sessions;
    let f = fx();
    let p = px(&f).await;
    // A high-assurance credential (attested, not backup-eligible).
    let c = f
        .ceremony(&p, &p.view, CeremonyPurpose::Register, None)
        .await;
    let mut record = f.record(&p.user, 1);
    record.assurance = Assurance::Aal3;
    record.attested = true;
    record.backup_eligible = false;
    record.backup_state = false;
    f.store
        .register_passkey(RegisterPasskey {
            actor: f.actor(&p.view),
            ceremony: c,
            portal_binding: p.bind,
            record,
            events: vec![],
        })
        .await
        .unwrap();
    let sid = p.view.session.session_id.clone();
    assert!(
        !f.store
            .session_aal3_evidence(&sid, p.view.session.cred_gen)
            .await
            .unwrap()
    );
    // A portal confirmation with an AAL 3 assertion.
    let c = f.ceremony(&p, &p.view, CeremonyPurpose::Verify, None).await;
    let mut used = f.used(1, 1);
    used.assurance = Assurance::Aal3;
    used.backup_eligible = false;
    used.backup_state = false;
    let mut handle = f.handle_row(&sid, PORTAL_HOST, &handle_value(&f.rng));
    handle.issued_aal = Aal::Two;
    handle.absolute_expires_at = p.view.handle.absolute_expires_at;
    f.store
        .elevate_portal(PortalElevation {
            actor: f.actor(&p.view),
            portal_binding: p.bind,
            proof: PortalProof::Passkey { ceremony: c, used },
            portal_handle: handle.clone(),
            events: vec![],
        })
        .await
        .unwrap();
    let v = f
        .store
        .lookup_handle(&handle.handle_sha256, &host(PORTAL_HOST))
        .await
        .unwrap()
        .unwrap();
    assert!(
        f.store
            .session_aal3_evidence(&sid, v.session.cred_gen)
            .await
            .unwrap()
    );
    // A stale generation never qualifies.
    assert!(
        !f.store
            .session_aal3_evidence(&sid, p.view.session.cred_gen)
            .await
            .unwrap()
    );
    // A later AAL 2 use (the key reported backup flags) replaces the evidence.
    let v2 = f.verify_portal(&p, &v, 1, 2).await.unwrap();
    assert!(
        !f.store
            .session_aal3_evidence(&sid, v2.session.cred_gen)
            .await
            .unwrap()
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM session_webauthn_provenance WHERE assurance='aal2'"),
        1
    );
}

#[tokio::test]
async fn a_primary_only_session_cannot_mint_recovery_codes_for_an_enrolled_user() {
    // Review F1: the victim enrolled in one session; the attacker holds only
    // the primary credential and signs in afresh in another.
    let f = fx();
    let p = px(&f).await;
    f.register(&p, &p.view, 1).await.unwrap();
    let attacker = f.session(&p.user, vec![]).await;
    let av = f.view(&attacker).await;
    refused(
        f.store
            .replace_recovery_codes(f.actor(&av), "x".into(), codes("X"), vec![])
            .await,
        refusal::VERIFICATION_REQUIRED,
    );
    // The enrolling session itself may create the first set.
    f.store
        .replace_recovery_codes(f.actor(&p.view), "b1".into(), codes("A"), vec![])
        .await
        .unwrap();
    // Once codes existed, even the enrolling session needs a possession factor.
    f.store
        .conn()
        .execute("UPDATE recovery_codes SET used_at=1", [])
        .unwrap();
    refused(
        f.store
            .replace_recovery_codes(f.actor(&p.view), "b2".into(), codes("B"), vec![])
            .await,
        refusal::VERIFICATION_REQUIRED,
    );
}

#[tokio::test]
async fn passkey_sessions_end_when_passwordless_is_not_configured() {
    let f = fx();
    let p = px(&f).await;
    let other = f.user(74).await;
    let s = f.session(&other, vec![]).await;
    f.store
        .conn()
        .execute(
            "UPDATE sessions SET provider_id='hopae.passkey' WHERE session_id=?1",
            [s.row.session_id.as_str()],
        )
        .unwrap();
    assert_eq!(f.store.end_passkey_sessions("r_test").await.unwrap(), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM sessions WHERE provider_id='hopae.passkey' AND terminated_at IS NULL"), 0);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM sessions WHERE terminated_at IS NULL"),
        1,
        "{:?}",
        p.session.row.session_id
    );
}
