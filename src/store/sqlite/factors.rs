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
                    let recent_mfa=actor.view.session.factors.iter().any(|factor| matches!(factor.kind,crate::session::types::FactorKind::Totp|crate::session::types::FactorKind::Webauthn) && factor.at<=shared.clock.now() && shared.clock.now().since(factor.at)<=std::time::Duration::from_secs(300));
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
    let live:bool=tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions s JOIN session_handles h ON h.session_id=s.session_id JOIN users u ON u.user_id=s.user_id JOIN providers p ON p.provider_id=s.provider_id WHERE s.session_id=?1 AND s.user_id=?2 AND h.handle_sha256=?3 AND h.host=?4 AND s.cred_gen=?5 AND s.auth_time=?6 AND s.authz_version_at_auth=u.authz_version AND u.status='active' AND s.terminated_at IS NULL AND h.revoked_at IS NULL AND p.enabled=1 AND p.deleted_at IS NULL AND s.aal>=?11 AND h.issued_aal>=?12 AND s.absolute_expires_at>?7 AND h.absolute_expires_at>?7 AND s.last_seen_at>?8 AND h.last_seen_at>?9 AND s.auth_time>=?10 AND s.auth_time<=?7 AND s.factors=?13)",
        params![view.session.session_id.as_str(),user,&view.handle.handle_sha256.0[..],view.handle.host.as_str(),view.session.cred_gen as i64,view.session.auth_time.secs(),now.secs(),now.secs().saturating_sub(actor.session_idle.as_secs() as i64),now.secs().saturating_sub(actor.handle_idle.as_secs() as i64),now.secs().saturating_sub(300),view.session.aal.as_i64().max(1),view.handle.issued_aal.as_i64().max(1),super::rows::json_str(&view.session.factors)?],|r|r.get(0),
    )?;
    if !live {
        return Err(StoreError::Conflict("factor authorization revoked"));
    }
    Ok(())
}
