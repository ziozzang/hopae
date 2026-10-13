//! Encrypted TOTP enrollment lifecycle and serialized monotonic counter consumption.
use super::{Store, commit, events::insert_events};
use crate::{
    event::types::{Event, EventBuilder, EventKind, Outcome},
    identity::types::UserId,
    store::{Factors, StoreError, StoreResult},
};
use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};

#[async_trait]
impl Factors for Store {
    async fn external_snapshot_revision(&self) -> StoreResult<u64> {
        self.read("external_snapshot_revision", external_snapshot_revision)
            .await
    }
    async fn publish_external_snapshot(
        &self,
        request: crate::store::ExternalFactorSnapshot,
    ) -> StoreResult<u64> {
        self.write("publish_external_snapshot", move |env| {
            let shared=env.shared.clone();let tx=env.begin()?;
            require_stepup_generation(&tx,Some(request.config_generation))?;
            if external_snapshot_revision(&tx)?!=request.expected_revision {
                return Err(StoreError::Conflict("external factor snapshot revision changed"));
            }
            if request.authorities.len()>64 {return Err(StoreError::Conflict("external factor capacity"));}
            let mut desired=std::collections::BTreeSet::new();
            for authority in &request.authorities {
                if !desired.insert(authority.factor.as_str()) {return Err(StoreError::Conflict("duplicate external factor id"));}
            }
            for authority in &request.authorities {
                apply_external_publication(&tx,&shared,&crate::store::ExternalFactorPublication {
                    factor:authority.factor.clone(),revision:authority.revision,binding:Some(authority.binding),config_generation:request.config_generation,
                })?;
            }
            let old:Vec<(String,i64,Option<Vec<u8>>)>=tx.prepare("SELECT factor,revision,binding FROM external_factor_authorities ORDER BY factor")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<Result<_,_>>()?;
            for (factor,revision,binding) in old {
                if !desired.contains(factor.as_str()) {
                    let revision=if binding.is_some() {revision.checked_add(1).ok_or(StoreError::Conflict("external factor revision exhausted"))?} else {revision};
                    apply_external_publication(&tx,&shared,&crate::store::ExternalFactorPublication {
                        factor,revision:u64::try_from(revision).map_err(|_|StoreError::Corrupt("external factor revision".into()))?,binding:None,config_generation:request.config_generation,
                    })?;
                }
            }
            let revision=advance_external_snapshot_revision(&tx)?;
            let event=EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::FactorRegistryPublished,Outcome::Success,"r_external_snapshot_publication").attr("count",request.authorities.len() as u64).build();
            insert_events(&tx,&shared,&[event])?;
            commit(tx,&shared,None)?;Ok(revision)
        }).await
    }
    async fn publish_external_factor(
        &self,
        request: crate::store::ExternalFactorPublication,
    ) -> StoreResult<()> {
        self.write("publish_external_factor", move |env| {
            let shared = env.shared.clone();
            let tx = env.begin()?;
            if apply_external_publication(&tx, &shared, &request)? {
                advance_external_snapshot_revision(&tx)?;
            }
            commit(tx, &shared, None)
        })
        .await
    }
    async fn bind_external_stepup(
        &self,
        request: crate::store::BindExternalStepUp,
    ) -> StoreResult<()> {
        self.write("bind_external_stepup", move |env| {
            let shared=env.shared.clone();let now=shared.clock.now();let tx=env.begin()?;
            let actor=&request.actor;let view=&actor.view;
            require_actor(&tx,&shared,actor.user().as_str(),actor)?;
            require_external_authority(&tx,&request.authority,request.config_generation)?;
            let context=external_context(view.session.cred_gen,&request.authority,request.config_generation)?;
            let params=params![&request.transaction.0[..],&request.portal_binding.0[..],&view.handle.handle_sha256.0[..],context,view.session.session_id.as_str(),actor.client_ip.to_string(),now.secs()];
            let changed=tx.execute("UPDATE login_txns SET portal_bind_sha256=?2,conflicting_handle_sha256=?3,pending_identity=?4 WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?5 AND client_ip=?6 AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=?7 AND expires_at>?7 AND portal_bind_sha256 IS NULL AND conflicting_handle_sha256 IS NULL AND pending_identity IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL",params)?;
            if changed!=1 {
                let identical:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM login_txns WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?5 AND client_ip=?6 AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=?7 AND expires_at>?7 AND portal_bind_sha256=?2 AND conflicting_handle_sha256=?3 AND pending_identity=?4 AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL)",params,|r|r.get(0))?;
                if !identical {return Err(StoreError::Conflict("external challenge unavailable"));}
            } else {
                let event=EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::LoginStarted,Outcome::Info,&actor.request_id).user(actor.user()).session(&view.session.session_id).reason(crate::event::types::reasons::STEP_UP_REQUIRED).attr("factor_id",request.authority.factor.as_str()).build();
                insert_events(&tx,&shared,&[event])?;
            }
            commit(tx,&shared,None)
        }).await
    }

    async fn bind_totp_stepup(
        &self,
        request: crate::store::BindTotpStepUp,
    ) -> StoreResult<crate::store::TotpChallengeBinding> {
        self.write("bind_totp_stepup", move |env| {
            let shared=env.shared.clone();let now=shared.clock.now();let tx=env.begin()?;
            let actor=&request.actor;let view=&actor.view;let user=actor.user();
            require_actor(&tx,&shared,user.as_str(),actor)?;
            require_stepup_generation(&tx,request.config_generation)?;
            let row:Option<(String,i64)> = tx.query_row("SELECT enrollment_id,revision FROM totp_enrollments WHERE user_id=?1 AND state='active'",[user.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let (enrollment,revision)=row.ok_or(StoreError::Conflict("active factor unavailable"))?;
            let context=stepup_context(view.session.cred_gen,&enrollment,revision,request.config_generation)?;
            let changed=tx.execute("UPDATE login_txns SET portal_bind_sha256=?2,conflicting_handle_sha256=?3,pending_identity=?4 WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?5 AND client_ip=?6 AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=?7 AND expires_at>?7 AND portal_bind_sha256 IS NULL AND conflicting_handle_sha256 IS NULL AND pending_identity IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL",
                params![&request.transaction.0[..],&request.portal_binding.0[..],&view.handle.handle_sha256.0[..],context,view.session.session_id.as_str(),actor.client_ip.to_string(),now.secs()])?;
            if changed!=1 {
                // Refresh is idempotent only for the identical bound browser,
                // live actor, generation and active enrollment revision.
                let matches:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM login_txns WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?5 AND client_ip=?6 AND bind_sha256 IS NOT NULL AND consumed_at IS NULL AND created_at<=?7 AND expires_at>?7 AND portal_bind_sha256=?2 AND conflicting_handle_sha256=?3 AND pending_identity=?4 AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND reauth_max_age IS NULL)",
                    params![&request.transaction.0[..],&request.portal_binding.0[..],&view.handle.handle_sha256.0[..],context,view.session.session_id.as_str(),actor.client_ip.to_string(),now.secs()],|r|r.get(0))?;
                if !matches {return Err(StoreError::Conflict("step-up challenge unavailable"));}
            }
            if changed==1 {
                let event=EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::LoginStarted,Outcome::Info,&actor.request_id).user(user).session(&view.session.session_id).reason(crate::event::types::reasons::STEP_UP_REQUIRED).attr("enrollment_id",enrollment.as_str()).build();
                insert_events(&tx,&shared,&[event])?;
            }
            let binding=crate::store::TotpChallengeBinding{enrollment,revision:u64::try_from(revision).map_err(|_|StoreError::Corrupt("factor revision".into()))?};
            commit(tx,&shared,None)?;
            Ok(binding)
        }).await
    }

    async fn elevate_external(&self, request: crate::store::ExternalElevation) -> StoreResult<()> {
        self.write("elevate_external", move |env| {
            use crate::{session::types::{Aal, FactorEntry, FactorKind}, event::types::reasons};
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            require_actor(&tx, &shared, user.as_str(), actor)?;
            let proof=&request.proof;
            require_external_authority(&tx,&proof.authority,request.config_generation)?;
            if proof.user!=user.as_str() || proof.session!=sid.as_str()
                || proof.challenge!=request.transaction.to_hex()
                || proof.credential_generation!=view.session.cred_gen
                || proof.verified_at>now || proof.expires_at<=now
                || proof.deadline<=std::time::Instant::now()
                || now.since(proof.verified_at)>std::time::Duration::from_secs(5)
                || proof.expires_at>proof.verified_at.add(std::time::Duration::from_secs(5)) {
                return Err(StoreError::Conflict("external proof context unavailable"));
            }
            let generation = view.session.cred_gen.checked_add(1).and_then(|n| i64::try_from(n).ok()).ok_or(StoreError::Conflict("credential generation exhausted"))?;
            let handle = &request.portal_handle;
            let code = &request.handoff;
            if handle.session_id != *sid || handle.host != view.handle.host
                || handle.handle_sha256 == view.handle.handle_sha256
                || handle.issued_aal != Aal::Two || handle.created_at.secs() != now.secs()
                || handle.last_seen_at.secs() != now.secs()
                || handle.absolute_expires_at.secs() <= now.secs()
                || handle.absolute_expires_at > view.handle.absolute_expires_at.min(view.session.absolute_expires_at)
                || handle.revoked_at.is_some() || handle.revoked_reason.is_some()
                || code.client_ip != actor.client_ip
                || code.session_id != *sid || code.issued_aal != Aal::Two
                || i64::try_from(code.cred_gen).ok() != Some(generation)
                || code.created_at.secs() != now.secs() || code.expires_at.secs() <= now.secs()
                || code.expires_at > now.add(std::time::Duration::from_secs(60)).min(view.session.absolute_expires_at)
                || code.consumed_at.is_some() || code.consumed_reason.is_some()
                || code.return_target.scheme() != "https" || code.return_target.host_str() != Some(code.host.as_str())
                || !code.return_target.username().is_empty() || code.return_target.password().is_some()
                || code.return_target.fragment().is_some()
            {
                return Err(StoreError::Conflict("invalid elevated credentials"));
            }
            // A native step-up challenge is bound to the initiating portal handle.
            // The existing conflicting-handle column has this purpose for stepup only.
            let consumed = tx.execute(
                "UPDATE login_txns SET consumed_at=?2,consumed_reason='elevation' WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?3 AND conflicting_handle_sha256=?4 AND bind_sha256=?5 AND return_target=?6 AND client_ip=?7 AND recovery_depth=?8 AND consumed_at IS NULL AND created_at<=?2 AND expires_at>?2 AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND portal_bind_sha256=?9 AND pending_identity=?10 AND app_id=?11",
                params![&request.transaction.0[..],now.secs(),sid.as_str(),&view.handle.handle_sha256.0[..],&code.bind_sha256.0[..],code.return_target.as_str(),code.client_ip.to_string(),i64::from(code.recovery_depth),&request.portal_binding.0[..],external_context(view.session.cred_gen,&proof.authority,request.config_generation)?,proof.service],
            )?;
            if consumed != 1 { return Err(StoreError::Conflict("step-up challenge unavailable")); }
            let revision=i64::try_from(proof.authority.revision).map_err(|_|StoreError::Conflict("invalid factor revision"))?;
            let inserted=tx.execute("INSERT INTO external_factor_proofs(factor,revision,proof_sha256,consumed_at_ms) SELECT ?1,?2,?3,?4 WHERE NOT EXISTS(SELECT 1 FROM external_factor_proofs WHERE factor=?1 AND revision=?2 AND proof_sha256=?3)",params![proof.authority.factor,revision,&proof.proof.0[..],now.0])?;
            if inserted!=1 {return Err(StoreError::Conflict("external proof already consumed"));}
            let mut factors = view.session.factors.clone();
            factors.push(FactorEntry { kind: FactorKind::External, provider: Some(crate::provider::types::ProviderId::new(format!("external:{}",proof.authority.factor))), at: now });
            tx.execute("INSERT INTO external_factor_sessions(factor,session_id,revision) VALUES(?1,?2,?3) ON CONFLICT(factor,session_id) DO UPDATE SET revision=excluded.revision",params![proof.authority.factor,sid.as_str(),revision])?;
            // An external second factor does not replace primary authentication time.
            tx.execute("UPDATE sessions SET aal=2,factors=?2,cred_gen=?3 WHERE session_id=?1",params![sid.as_str(),super::rows::json_str(&factors)?,generation])?;
            let mut events = request.events;
            let live:Vec<String> = tx.prepare("SELECT host FROM session_handles WHERE session_id=?1 AND revoked_at IS NULL ORDER BY host,handle_sha256")?.query_map([sid.as_str()],|r|r.get(0))?.collect::<Result<_,_>>()?;
            for host in live {
                events.push(EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::HandleRevoked,Outcome::Success,&actor.request_id).user(user).session(sid).reason(reasons::ELEVATION).attr("host",host).build());
            }
            super::sessions::revoke_session_handles(&tx,sid,reasons::ELEVATION.0,now)?;
            super::sessions::consume_session_codes(&tx,sid,reasons::ELEVATION.0,now)?;
            super::sessions::insert_handle(&tx,handle)?;
            super::sessions::insert_handoff_code(&tx,code)?;
            events.push(EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::FactorExternalConsumed,Outcome::Success,&actor.request_id).user(user).session(sid).reason(reasons::ELEVATION).attr("factor_id",proof.authority.factor.as_str()).build());
            events.push(EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::SessionHandoff,Outcome::Success,&actor.request_id).user(user).session(sid).reason(reasons::ELEVATION).attr("host",code.host.as_str()).build());
            insert_events(&tx,&shared,&events)?;
            let final_now=shared.clock.now();
            if proof.deadline<=std::time::Instant::now() || proof.expires_at<=final_now || final_now<proof.verified_at {
                return Err(StoreError::Conflict("external proof expired before commit"));
            }
            commit(tx,&shared,None)
        }).await
    }

    async fn elevate_totp(&self, request: crate::store::TotpElevation) -> StoreResult<()> {
        self.write("elevate_totp", move |env| {
            use crate::{session::types::{Aal, FactorEntry, FactorKind}, event::types::reasons};
            let shared = env.shared.clone();
            let now = shared.clock.now();
            let tx = env.begin()?;
            let actor = &request.actor;
            let view = &actor.view;
            let user = actor.user();
            let sid = &view.session.session_id;
            require_actor(&tx, &shared, user.as_str(), actor)?;
            require_stepup_generation(&tx,request.config_generation)?;
            let revision = i64::try_from(request.revision).map_err(|_| StoreError::Conflict("invalid enrollment revision"))?;
            let counter = i64::try_from(request.counter).map_err(|_| StoreError::Conflict("invalid OTP counter"))?;
            let generation = view.session.cred_gen.checked_add(1).and_then(|n| i64::try_from(n).ok()).ok_or(StoreError::Conflict("credential generation exhausted"))?;
            let handle = &request.portal_handle;
            let code = &request.handoff;
            if handle.session_id != *sid || handle.host != view.handle.host
                || handle.handle_sha256 == view.handle.handle_sha256
                || handle.issued_aal != Aal::Two || handle.created_at.secs() != now.secs()
                || handle.last_seen_at.secs() != now.secs()
                || handle.absolute_expires_at.secs() <= now.secs()
                || handle.absolute_expires_at > view.handle.absolute_expires_at.min(view.session.absolute_expires_at)
                || handle.revoked_at.is_some() || handle.revoked_reason.is_some()
                || code.client_ip != actor.client_ip
                || code.session_id != *sid || code.issued_aal != Aal::Two
                || i64::try_from(code.cred_gen).ok() != Some(generation)
                || code.created_at.secs() != now.secs() || code.expires_at.secs() <= now.secs()
                || code.expires_at > now.add(std::time::Duration::from_secs(60)).min(view.session.absolute_expires_at)
                || code.consumed_at.is_some() || code.consumed_reason.is_some()
                || code.return_target.scheme() != "https" || code.return_target.host_str() != Some(code.host.as_str())
                || !code.return_target.username().is_empty() || code.return_target.password().is_some()
                || code.return_target.fragment().is_some()
            {
                return Err(StoreError::Conflict("invalid elevated credentials"));
            }
            // A native step-up challenge is bound to the initiating portal handle.
            // The existing conflicting-handle column has this purpose for stepup only.
            let consumed = tx.execute(
                "UPDATE login_txns SET consumed_at=?2,consumed_reason='elevation' WHERE txn_sha256=?1 AND purpose='stepup' AND portal_session_id=?3 AND conflicting_handle_sha256=?4 AND bind_sha256=?5 AND return_target=?6 AND client_ip=?7 AND recovery_depth=?8 AND consumed_at IS NULL AND created_at<=?2 AND expires_at>?2 AND reauth_max_age IS NULL AND provider_id IS NULL AND state_sha256 IS NULL AND nonce IS NULL AND pkce_verifier IS NULL AND portal_bind_sha256=?9 AND pending_identity=?10",
                params![&request.transaction.0[..],now.secs(),sid.as_str(),&view.handle.handle_sha256.0[..],&code.bind_sha256.0[..],code.return_target.as_str(),code.client_ip.to_string(),i64::from(code.recovery_depth),&request.portal_binding.0[..],stepup_context(view.session.cred_gen,&request.enrollment,revision,request.config_generation)?],
            )?;
            if consumed != 1 { return Err(StoreError::Conflict("step-up challenge unavailable")); }
            if tx.execute("UPDATE totp_enrollments SET last_counter=?4,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='active' AND last_counter<?4",params![request.enrollment,user.as_str(),revision,counter,now.secs()])? != 1 {
                return Err(StoreError::Conflict("factor proof unavailable"));
            }
            let mut factors = view.session.factors.clone();
            factors.push(FactorEntry { kind: FactorKind::Totp, provider: None, at: now });
            // Preserve the primary authentication time: OTP is not provider reauthentication.
            tx.execute("UPDATE sessions SET aal=2,factors=?2,cred_gen=?3 WHERE session_id=?1",params![sid.as_str(),super::rows::json_str(&factors)?,generation])?;
            let mut events = request.events;
            let live:Vec<String> = tx.prepare("SELECT host FROM session_handles WHERE session_id=?1 AND revoked_at IS NULL ORDER BY host,handle_sha256")?.query_map([sid.as_str()],|r|r.get(0))?.collect::<Result<_,_>>()?;
            for host in live {
                events.push(EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::HandleRevoked,Outcome::Success,&actor.request_id).user(user).session(sid).reason(reasons::ELEVATION).attr("host",host).build());
            }
            super::sessions::revoke_session_handles(&tx,sid,reasons::ELEVATION.0,now)?;
            super::sessions::consume_session_codes(&tx,sid,reasons::ELEVATION.0,now)?;
            super::sessions::insert_handle(&tx,handle)?;
            super::sessions::insert_handoff_code(&tx,code)?;
            let mut proof_event=factor_event(&shared,user,&request.enrollment,EventKind::FactorTotpConsumed,&actor.request_id);
            proof_event.session_id=Some(sid.clone());proof_event.reason=Some(reasons::ELEVATION);
            events.push(proof_event);
            events.push(EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::SessionHandoff,Outcome::Success,&actor.request_id).user(user).session(sid).reason(reasons::ELEVATION).attr("host",code.host.as_str()).build());
            insert_events(&tx,&shared,&events)?;
            commit(tx,&shared,None)
        }).await
    }

    async fn has_active_totp(&self, user: &UserId) -> StoreResult<bool> {
        let user = user.clone();
        self.read("has_active_totp",move |conn| {
            Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM totp_enrollments t JOIN users u ON u.user_id=t.user_id WHERE t.user_id=?1 AND t.state='active' AND u.status='active')",[user.as_str()],|row|row.get(0))?)
        }).await
    }

    async fn activate_totp_authorized(
        &self,
        id: &str,
        actor: crate::store::FactorActor,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let user = actor.user().clone();
        self.mutate_totp(
            id,
            &user,
            revision,
            Some(counter),
            ("activate", Some(actor)),
            events,
        )
        .await
    }
    async fn revoke_totp_authorized(
        &self,
        id: &str,
        actor: crate::store::FactorActor,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let user = actor.user().clone();
        self.mutate_totp(id, &user, revision, None, ("revoke", Some(actor)), events)
            .await
    }

    async fn totp_enrollment(
        &self,
        id: &str,
        user: &UserId,
    ) -> StoreResult<Option<crate::store::TotpEnrollment>> {
        let (id, user) = (id.to_owned(), user.clone());
        let clock = self.inner.shared.clock.clone();
        self.read("totp_enrollment",move |conn| {
            let row: Option<(i64,String,Option<i64>,String)>=conn.query_row(
                "SELECT revision,state,last_counter,envelope FROM totp_enrollments WHERE enrollment_id=?1 AND user_id=?2 AND state!='revoked' AND (state='active' OR pending_expires_at>?3) AND EXISTS(SELECT 1 FROM users WHERE user_id=?2 AND status='active')",
                params![id,user.as_str(),clock.now().secs()],
                |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional()?;
            row.map(|(revision,state,counter,envelope)| {
                let revision=u64::try_from(revision).ok().filter(|n|*n>0).ok_or_else(||StoreError::Corrupt("totp revision".into()))?;
                let last_counter=counter.map(u64::try_from).transpose().map_err(|_|StoreError::Corrupt("totp counter".into()))?;
                let envelope=crate::factor::seed_cipher::Envelope::from_json(&envelope).map_err(|_|StoreError::Corrupt("totp envelope".into()))?;
                Ok(crate::store::TotpEnrollment { enrollment_id:id,user_id:user,revision,active:state=="active",last_counter,envelope })
            }).transpose()
        }).await
    }

    async fn create_totp_pending_authorized(
        &self,
        id: String,
        actor: crate::store::FactorActor,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.create_pending_with_actor(id, actor.user().clone(), envelope, events, Some(actor))
            .await
    }
    async fn create_totp_pending(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        self.create_pending_with_actor(id, user, envelope, events, None)
            .await
    }
    async fn activate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(
            id,
            user,
            revision,
            Some(counter),
            ("activate", None),
            events,
        )
        .await
    }
    async fn consume_totp_counter(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(id, user, revision, Some(counter), ("consume", None), events)
            .await
    }
    async fn revoke_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(id, user, revision, None, ("revoke", None), events)
            .await
    }
}
impl Store {
    async fn create_pending_with_actor(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
        actor: Option<crate::store::FactorActor>,
    ) -> StoreResult<()> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(StoreError::Conflict("invalid enrollment id"));
        }
        let envelope = serde_json::to_string(&envelope)
            .map_err(|_| StoreError::Corrupt("totp envelope".into()))?;
        crate::factor::seed_cipher::Envelope::from_json(&envelope)
            .map_err(|_| StoreError::Corrupt("totp envelope".into()))?;
        self.write("create_totp_pending",move |env| {
            let shared=env.shared.clone();let now=shared.clock.now().secs();let tx=env.begin()?;
            let active: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=?1 AND status='active')",[user.as_str()],|r|r.get(0))?;
            if !active { return Err(StoreError::Conflict("user unavailable")); }
            if let Some(actor)=&actor {
                require_actor(&tx,&shared,user.as_str(),actor)?;
                let enrolled:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM totp_enrollments WHERE user_id=?1 AND state='active')",[user.as_str()],|row|row.get(0))?;
                if enrolled { return Err(StoreError::Conflict("active factor requires replacement flow")); }
            }

            let expired: Option<String> = tx.query_row("SELECT enrollment_id FROM totp_enrollments WHERE user_id=?1 AND state='pending' AND pending_expires_at<=?2",params![user.as_str(),now],|row|row.get(0)).optional()?;
            if let Some(expired)=expired {
                tx.execute("UPDATE totp_enrollments SET state='revoked',revision=revision+1,pending_expires_at=NULL,updated_at=?2 WHERE enrollment_id=?1",params![expired,now])?;
                insert_events(&tx,&shared,&[factor_event(&shared,&user,&expired,EventKind::FactorEnrollmentExpired,actor.as_ref().map(|a|a.request_id.as_str()).unwrap_or("r_totp_store"))])?;
            }
            tx.execute("INSERT INTO totp_enrollments(enrollment_id,user_id,envelope,revision,state,pending_expires_at,created_at,updated_at)VALUES(?1,?2,?3,1,'pending',?4,?5,?5)",params![id,user.as_str(),envelope,now.saturating_add(600),now])?;
            insert_events(&tx,&shared,&[factor_event(&shared,&user,&id,EventKind::FactorEnrollmentPrepared,actor.as_ref().map(|a|a.request_id.as_str()).unwrap_or("r_totp_store"))])?;
            insert_events(&tx,&shared,&events)?;commit(tx,&shared,None)
        }).await
    }
    async fn mutate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: Option<u64>,
        authorization: (&'static str, Option<crate::store::FactorActor>),
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let (operation, actor) = authorization;
        let (id, user) = (id.to_owned(), user.clone());
        let revision = i64::try_from(revision)
            .map_err(|_| StoreError::Conflict("invalid enrollment revision"))?;
        let counter = counter
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::Conflict("invalid OTP counter"))?;
        self.write("mutate_totp",move |env| {
            let shared=env.shared.clone();let now=shared.clock.now().secs();let tx=env.begin()?;
            let was_active = operation=="revoke" && tx.query_row("SELECT EXISTS(SELECT 1 FROM totp_enrollments WHERE enrollment_id=?1 AND user_id=?2 AND state='active')",params![id,user.as_str()],|row|row.get::<_,bool>(0))?;
            if let Some(actor)=&actor {
                require_actor(&tx,&shared,user.as_str(),actor)?;
                if operation=="revoke" {
                    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM totp_enrollments WHERE enrollment_id=?1 AND user_id=?2 AND state='active')",params![id,user.as_str()],|row|row.get(0))?;
                    let recent_mfa=actor.view.session.factors.iter().any(|factor| matches!(factor.kind,crate::session::types::FactorKind::Totp|crate::session::types::FactorKind::Webauthn|crate::session::types::FactorKind::External) && factor.at<=shared.clock.now() && shared.clock.now().since(factor.at)<=std::time::Duration::from_secs(300));
                    if active && (actor.view.session.aal < crate::session::types::Aal::Two || actor.view.handle.issued_aal < crate::session::types::Aal::Two || !recent_mfa) {
                        return Err(StoreError::Conflict("active factor removal requires step-up"));
                    }
                }
            }
            let sql=match operation {
                "activate" => "UPDATE totp_enrollments SET state='active',revision=revision+1,last_counter=?4,pending_expires_at=NULL,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='pending' AND pending_expires_at>?5 AND EXISTS(SELECT 1 FROM users WHERE user_id=?2 AND status='active')",
                "consume" => "UPDATE totp_enrollments SET last_counter=?4,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='active' AND last_counter<?4 AND EXISTS(SELECT 1 FROM users WHERE user_id=?2 AND status='active')",
                "revoke" => "UPDATE totp_enrollments SET state='revoked',revision=revision+1,pending_expires_at=NULL,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state!='revoked' AND ?4 IS NULL",
                _ => return Err(StoreError::Conflict("invalid factor operation")),
            };
            if tx.execute(sql,params![id,user.as_str(),revision,counter,now])?!=1 { return Ok(false); }
            if was_active {
                let sessions:Vec<String>=tx.prepare("SELECT session_id FROM sessions WHERE user_id=?1 AND terminated_at IS NULL ORDER BY session_id")?.query_map([user.as_str()],|row|row.get(0))?.collect::<Result<_,_>>()?;
                for id in sessions {
                    let session=crate::session::types::SessionId::new(id);
                    let event=EventBuilder::new(shared.clock.as_ref(),shared.rng().as_ref(),EventKind::SessionTerminated,Outcome::Success,"r_totp_store")
                        .user(&user).session(&session).reason(crate::event::types::reasons::FACTOR_REVOKED).build();
                    super::sessions::terminate_in(&tx,&shared,&session,crate::event::types::reasons::FACTOR_REVOKED,crate::crypto::Timestamp::from_secs(now),&[event])?;
                }
            }
            let kind=match operation { "activate"=>EventKind::FactorEnrollmentActivated,"consume"=>EventKind::FactorTotpConsumed,_=>EventKind::FactorEnrollmentRevoked };
            insert_events(&tx,&shared,&[factor_event(&shared,&user,&id,kind,actor.as_ref().map(|a|a.request_id.as_str()).unwrap_or("r_totp_store"))])?;
            insert_events(&tx,&shared,&events)?;commit(tx,&shared,None)?;Ok(true)
        }).await
    }
}

fn factor_event(
    shared: &super::Shared,
    user: &UserId,
    id: &str,
    kind: EventKind,
    request_id: &str,
) -> Event {
    EventBuilder::new(
        shared.clock.as_ref(),
        shared.rng().as_ref(),
        kind,
        Outcome::Success,
        request_id,
    )
    .user(user)
    .attr("enrollment_id", id)
    .build()
}

fn require_actor(
    tx: &rusqlite::Transaction<'_>,
    shared: &super::Shared,
    user: &str,
    actor: &crate::store::FactorActor,
) -> StoreResult<()> {
    let now = shared.clock.now();
    if now < actor.authorized_at
        || now.since(actor.authorized_at) > std::time::Duration::from_secs(5)
    {
        return Err(StoreError::Conflict("factor authorization expired"));
    }
    let view = &actor.view;
    super::sessions::require_provider_configuration(
        tx,
        view.session.provider_id.as_str(),
        Some(&actor.provider_configuration),
    )?;
    let live:bool=tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions s JOIN session_handles h ON h.session_id=s.session_id JOIN users u ON u.user_id=s.user_id JOIN providers p ON p.provider_id=s.provider_id WHERE s.session_id=?1 AND s.user_id=?2 AND h.handle_sha256=?3 AND h.host=?4 AND s.cred_gen=?5 AND s.auth_time=?6 AND s.authz_version_at_auth=u.authz_version AND u.status='active' AND s.terminated_at IS NULL AND h.revoked_at IS NULL AND p.enabled=1 AND p.deleted_at IS NULL AND s.aal>=?11 AND h.issued_aal>=?12 AND s.absolute_expires_at>?7 AND h.absolute_expires_at>?7 AND s.last_seen_at>?8 AND h.last_seen_at>?9 AND s.auth_time>=?10 AND s.auth_time<=?7 AND s.factors=?13)",
        params![view.session.session_id.as_str(),user,&view.handle.handle_sha256.0[..],view.handle.host.as_str(),view.session.cred_gen as i64,view.session.auth_time.secs(),now.secs(),now.secs().saturating_sub(actor.session_idle.as_secs() as i64),now.secs().saturating_sub(actor.handle_idle.as_secs() as i64),now.secs().saturating_sub(300),view.session.aal.as_i64().max(1),view.handle.issued_aal.as_i64().max(1),super::rows::json_str(&view.session.factors)?],|r|r.get(0),
    )?;
    if !live {
        return Err(StoreError::Conflict("factor authorization revoked"));
    }
    Ok(())
}

fn stepup_context(
    generation: u64,
    enrollment: &str,
    revision: i64,
    config_generation: Option<u64>,
) -> StoreResult<String> {
    if revision <= 0 || i64::try_from(generation).is_err() {
        return Err(StoreError::Conflict("invalid step-up context"));
    }
    Ok(serde_json::json!({"credential_generation":generation,"enrollment_id":enrollment,"enrollment_revision":revision,"config_generation":config_generation.unwrap_or(0)}).to_string())
}

fn require_stepup_generation(
    tx: &rusqlite::Transaction<'_>,
    expected: Option<u64>,
) -> StoreResult<()> {
    if let Some(expected) = expected {
        if expected == 0 {
            return Err(StoreError::Conflict("step-up configuration unavailable"));
        }
        let current: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='config_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if current.and_then(|s| s.parse::<u64>().ok()) != Some(expected) {
            return Err(StoreError::Conflict("step-up configuration changed"));
        }
    }
    Ok(())
}

fn require_external_authority(
    tx: &rusqlite::Transaction<'_>,
    authority: &crate::factor::external_transport::Authority,
    generation: u64,
) -> StoreResult<()> {
    require_stepup_generation(tx, Some(generation))?;
    let revision = i64::try_from(authority.revision)
        .map_err(|_| StoreError::Conflict("invalid factor revision"))?;
    let generation = i64::try_from(generation)
        .map_err(|_| StoreError::Conflict("invalid configuration generation"))?;
    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM external_factor_authorities WHERE factor=?1 AND revision=?2 AND binding=?3 AND config_generation=?4)",params![authority.factor,revision,&authority.binding[..],generation],|r|r.get(0))?;
    if !active {
        return Err(StoreError::Conflict("external factor disabled or changed"));
    }
    Ok(())
}
fn external_context(
    generation: u64,
    authority: &crate::factor::external_transport::Authority,
    configuration: u64,
) -> StoreResult<String> {
    if i64::try_from(generation).is_err() {
        return Err(StoreError::Conflict("invalid credential generation"));
    }
    Ok(serde_json::json!({"kind":"external","credential_generation":generation,"factor":authority.factor,"revision":authority.revision,"binding":crate::crypto::Digest(authority.binding).to_hex(),"config_generation":configuration}).to_string())
}

fn apply_external_publication(
    tx: &rusqlite::Transaction<'_>,
    shared: &super::Shared,
    request: &crate::store::ExternalFactorPublication,
) -> StoreResult<bool> {
    require_stepup_generation(tx, Some(request.config_generation))?;
    let revision = i64::try_from(request.revision)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(StoreError::Conflict("invalid external factor revision"))?;
    if request.factor.is_empty()
        || request.factor.len() > 128
        || !request
            .factor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(StoreError::Conflict("invalid external factor id"));
    }
    let old:Option<(i64,Option<Vec<u8>>,i64)>=tx.query_row("SELECT revision,binding,config_generation FROM external_factor_authorities WHERE factor=?1",[&request.factor],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((old_revision, old_binding, old_generation)) = old {
        if u64::try_from(old_generation)
            .ok()
            .is_none_or(|g| g > request.config_generation)
        {
            return Err(StoreError::Conflict(
                "external factor configuration epoch decreased",
            ));
        }
        if revision < old_revision
            || (revision == old_revision
                && old_binding.as_deref() != request.binding.as_ref().map(|b| b.as_slice()))
        {
            return Err(StoreError::Conflict("external factor revision changed"));
        }
        if revision == old_revision && old_generation as u64 == request.config_generation {
            return Ok(false);
        }
        if revision != old_revision
            || old_binding.as_deref() != request.binding.as_ref().map(|b| b.as_slice())
        {
            let sessions:Vec<(String,String)>=tx.prepare("SELECT s.session_id,s.user_id FROM external_factor_sessions e JOIN sessions s ON s.session_id=e.session_id WHERE e.factor=?1 AND s.terminated_at IS NULL")?.query_map([&request.factor],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<Result<_,_>>()?;
            for (sid, user) in sessions {
                let sid = crate::session::types::SessionId::new(sid);
                let user = UserId::new(user);
                let event = EventBuilder::new(
                    shared.clock.as_ref(),
                    shared.rng().as_ref(),
                    EventKind::SessionTerminated,
                    Outcome::Success,
                    "r_external_factor_publication",
                )
                .user(&user)
                .session(&sid)
                .reason(crate::event::types::reasons::FACTOR_REVOKED)
                .attr("factor_id", request.factor.as_str())
                .build();
                super::sessions::terminate_in(
                    tx,
                    shared,
                    &sid,
                    crate::event::types::reasons::FACTOR_REVOKED,
                    shared.clock.now(),
                    &[event],
                )?;
            }
        }
    } else {
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM external_factor_authorities",
            [],
            |r| r.get(0),
        )?;
        if count >= 64 {
            return Err(StoreError::Conflict("external factor capacity"));
        }
    }
    tx.execute("INSERT INTO external_factor_authorities(factor,revision,binding,config_generation) VALUES(?1,?2,?3,?4) ON CONFLICT(factor) DO UPDATE SET revision=excluded.revision,binding=excluded.binding,config_generation=excluded.config_generation",params![request.factor,revision,request.binding.as_ref().map(|b|b.as_slice()),i64::try_from(request.config_generation).map_err(|_|StoreError::Conflict("invalid configuration generation"))?])?;
    let event = EventBuilder::new(
        shared.clock.as_ref(),
        shared.rng().as_ref(),
        EventKind::FactorAuthorityPublished,
        Outcome::Success,
        "r_external_factor_publication",
    )
    .attr("factor_id", request.factor.as_str())
    .build();
    insert_events(tx, shared, &[event])?;
    Ok(true)
}
fn external_snapshot_revision(conn: &rusqlite::Connection) -> StoreResult<u64> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='external_factor_snapshot_revision'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match value {
        None => Ok(0),
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0 && *v <= i64::MAX as u64)
            .ok_or(StoreError::Corrupt(
                "external factor snapshot revision".into(),
            )),
    }
}
fn advance_external_snapshot_revision(tx: &rusqlite::Transaction<'_>) -> StoreResult<u64> {
    let revision = external_snapshot_revision(tx)?
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(StoreError::Conflict("external snapshot revision exhausted"))?;
    tx.execute("INSERT INTO meta(key,value) VALUES('external_factor_snapshot_revision',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[revision.to_string()])?;
    Ok(revision)
}
