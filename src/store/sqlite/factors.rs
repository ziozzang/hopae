//! Encrypted TOTP enrollment lifecycle and serialized monotonic counter consumption.
use super::{Store, commit, events::insert_events};
use crate::{
    event::types::Event,
    identity::types::UserId,
    store::{Factors, StoreError, StoreResult},
};
use async_trait::async_trait;
use rusqlite::{OptionalExtension, params};

#[async_trait]
impl Factors for Store {
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

    async fn create_totp_pending(
        &self,
        id: String,
        user: UserId,
        envelope: crate::factor::seed_cipher::Envelope,
        events: Vec<Event>,
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
            tx.execute("INSERT INTO totp_enrollments(enrollment_id,user_id,envelope,revision,state,pending_expires_at,created_at,updated_at)VALUES(?1,?2,?3,1,'pending',?4,?5,?5)",params![id,user.as_str(),envelope,now.saturating_add(600),now])?;
            insert_events(&tx,&shared,&events)?;commit(tx,&shared,None)
        }).await
    }
    async fn activate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(id, user, revision, Some(counter), "activate", events)
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
        self.mutate_totp(id, user, revision, Some(counter), "consume", events)
            .await
    }
    async fn revoke_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        self.mutate_totp(id, user, revision, None, "revoke", events)
            .await
    }
}
impl Store {
    async fn mutate_totp(
        &self,
        id: &str,
        user: &UserId,
        revision: u64,
        counter: Option<u64>,
        operation: &'static str,
        events: Vec<Event>,
    ) -> StoreResult<bool> {
        let (id, user) = (id.to_owned(), user.clone());
        let revision = i64::try_from(revision)
            .map_err(|_| StoreError::Conflict("invalid enrollment revision"))?;
        let counter = counter
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::Conflict("invalid OTP counter"))?;
        self.write("mutate_totp",move |env| {
            let shared=env.shared.clone();let now=shared.clock.now().secs();let tx=env.begin()?;
            let sql=match operation {
                "activate" => "UPDATE totp_enrollments SET state='active',revision=revision+1,last_counter=?4,pending_expires_at=NULL,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='pending' AND pending_expires_at>?5 AND EXISTS(SELECT 1 FROM users WHERE user_id=?2 AND status='active')",
                "consume" => "UPDATE totp_enrollments SET last_counter=?4,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state='active' AND last_counter<?4 AND EXISTS(SELECT 1 FROM users WHERE user_id=?2 AND status='active')",
                "revoke" => "UPDATE totp_enrollments SET state='revoked',revision=revision+1,pending_expires_at=NULL,updated_at=?5 WHERE enrollment_id=?1 AND user_id=?2 AND revision=?3 AND state!='revoked' AND ?4 IS NULL",
                _ => return Err(StoreError::Conflict("invalid factor operation")),
            };
            if tx.execute(sql,params![id,user.as_str(),revision,counter,now])?!=1 { return Ok(false); }
            insert_events(&tx,&shared,&events)?;commit(tx,&shared,None)?;Ok(true)
        }).await
    }
}
