//! `CoreStore` (ADR-0020 slice 1) for SQLite: delegation to the existing
//! traits, plus the two outbox reads the contract adds.
use async_trait::async_trait;

use super::Store;
use super::rows::{self, EVENT_COLS, cols};
use crate::crypto::{Digest, Timestamp};
use crate::event::types::{Event, Reason};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::policy::types::Host;
use crate::provider::types::ProviderId;
use crate::session::types::SessionId;
use crate::store::core::CoreStore;
use crate::store::types::*;
use crate::store::{Directory, Events, Sessions, StoreResult};

#[async_trait]
impl CoreStore for Store {
    fn backend(&self) -> &'static str {
        "sqlite"
    }
    async fn ensure_provider(&self, row: ProviderRow) -> StoreResult<()> {
        Directory::import_providers(self, vec![row], None, vec![])
            .await
            .map(|_| ())
    }
    async fn user(&self, id: &UserId) -> StoreResult<Option<User>> {
        Directory::user(self, id).await
    }
    async fn user_authz(&self, id: &UserId) -> StoreResult<Option<UserAuthz>> {
        Directory::user_authz(self, id).await
    }
    async fn user_by_email(&self, email: &NormalizedEmail) -> StoreResult<Option<User>> {
        Directory::user_by_email(self, email).await
    }
    async fn identity(
        &self,
        provider: &ProviderId,
        subject: &str,
    ) -> StoreResult<Option<IdentityRow>> {
        Directory::identity(self, provider, subject).await
    }
    async fn create_user(
        &self,
        user: NewUser,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<User> {
        Directory::create_user(self, user, identity, events).await
    }
    async fn link_identity(
        &self,
        user: &UserId,
        identity: NewIdentity,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Directory::link_identity(self, user, identity, events).await
    }
    async fn touch_identity(
        &self,
        provider: &ProviderId,
        subject: &str,
        seen: &NewIdentity,
        at: Timestamp,
    ) -> StoreResult<()> {
        Directory::touch_identity(self, provider, subject, seen, at).await
    }
    async fn create_session(&self, req: CreateSession) -> StoreResult<()> {
        Sessions::create_session(self, req).await
    }
    async fn session(&self, id: &SessionId) -> StoreResult<Option<SessionRow>> {
        Sessions::session(self, id).await
    }
    async fn lookup_handle(
        &self,
        handle_sha256: &Digest,
        host: &Host,
    ) -> StoreResult<Option<HandleView>> {
        Sessions::lookup_handle(self, handle_sha256, host).await
    }
    async fn touch_handle(&self, handle_sha256: &Digest, at: Timestamp) -> StoreResult<()> {
        Sessions::touch_handle(self, handle_sha256, at).await
    }
    async fn revoke_handle(
        &self,
        handle_sha256: &Digest,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Sessions::revoke_handle(self, handle_sha256, reason, at, events).await
    }
    async fn terminate_session(
        &self,
        id: &SessionId,
        reason: Reason,
        at: Timestamp,
        events: Vec<Event>,
    ) -> StoreResult<()> {
        Sessions::terminate_session(self, id, reason, at, events).await
    }
    async fn append_required(&self, events: Vec<Event>) -> StoreResult<()> {
        Events::append_required(self, events).await
    }
    async fn recent_events(&self, limit: usize) -> StoreResult<Vec<Event>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        self.read("recent_events", move |c| {
            let sql = format!(
                "SELECT {} FROM events ORDER BY at DESC, event_id DESC LIMIT ?1",
                cols("", EVENT_COLS)
            );
            let mut st = c.prepare(&sql)?;
            let mut q = st.query([limit])?;
            let mut out = Vec::new();
            while let Some(r) = q.next()? {
                out.push(rows::event(r, 0)?);
            }
            out.reverse();
            Ok(out)
        })
        .await
    }
    async fn pending_deliveries(&self, event: &str) -> StoreResult<Vec<String>> {
        let event = event.to_owned();
        self.read("pending_deliveries", move |c| {
            let mut st = c.prepare(
                "SELECT sink FROM event_deliveries WHERE event_id=?1 AND state='pending' ORDER BY sink",
            )?;
            let rows = st
                .query_map([event], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }
}
