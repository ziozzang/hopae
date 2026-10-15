//! One bounded storage snapshot for an actual native Engine witness.
use super::{
    Store,
    provider_owner::PreparedProviders,
    rows::{self, HANDLE_COLS, SESSION_COLS, blob, cols},
};
use crate::{
    crypto::Timestamp,
    policy::step_up,
    session::Aal,
    store::{Deadline, HandleView, StoreError, StoreResult, UserStatus},
    verify::{
        human::Witness,
        lifetimes::{self, LifetimeVerdict},
    },
};
use rusqlite::{OptionalExtension, params};
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Current {
    realm: String,
    factor: Option<super::totp_owner::Facts>,
    primary: super::primary_owner::Facts,
    pub(crate) expires: Timestamp,
}
fn refused() -> StoreError {
    StoreError::Conflict("native Human durable owner changed")
}
fn snapshot_eq(a: &crate::store::IdentitySnapshot, b: &crate::store::IdentitySnapshot) -> bool {
    a.email == b.email
        && a.display_name == b.display_name
        && a.username == b.username
        && a.groups == b.groups
}
fn same(a: &HandleView, b: &HandleView) -> bool {
    let (a_h, b_h, a_s, b_s) = (&a.handle, &b.handle, &a.session, &b.session);
    a_h.handle_sha256 == b_h.handle_sha256
        && a_h.session_id == b_h.session_id
        && a_h.host == b_h.host
        && a_h.issued_aal == b_h.issued_aal
        && a_h.created_at == b_h.created_at
        && a_h.absolute_expires_at == b_h.absolute_expires_at
        && a_h.last_seen_at >= b_h.last_seen_at
        && a_h.revoked_at.is_none()
        && a_s.session_id == b_s.session_id
        && a_s.user_id == b_s.user_id
        && a_s.provider_id == b_s.provider_id
        && a_s.auth_time == b_s.auth_time
        && a_s.auth_time_source == b_s.auth_time_source
        && a_s.factors == b_s.factors
        && a_s.aal == b_s.aal
        && a_s.authz_version == b_s.authz_version
        && a_s.cred_gen == b_s.cred_gen
        && snapshot_eq(&a_s.snapshot, &b_s.snapshot)
        && a_s.bound_ip == b_s.bound_ip
        && a_s.bound_ua_sha256 == b_s.bound_ua_sha256
        && a_s.created_at == b_s.created_at
        && a_s.absolute_expires_at == b_s.absolute_expires_at
        && a_s.last_seen_at >= b_s.last_seen_at
        && a_s.terminated_at.is_none()
        && a_s.authz_version_at_auth == b_s.authz_version_at_auth
        && a.user.status == UserStatus::Active
        && a.user.authz_version == b.user.authz_version
        && a.user.groups == b.user.groups
}
impl Store {
    pub(crate) async fn require_human_snapshot(
        &self,
        prepared: &PreparedProviders,
        materials: &super::material_owner::Published,
        witness: &Witness,
        now: Timestamp,
        deadline: Deadline,
    ) -> StoreResult<Current> {
        let (generation, revision) =
            prepared.human_expected(self, &witness.view.session.provider_id)?;
        if generation != witness.snapshot.generation {
            return Err(refused());
        }
        let material = materials.expected(self, witness.view.session.provider_id.as_str())?;
        let expected = witness.view.clone();
        let app = witness.app.clone();
        let policy = witness.session_policy;
        let path = witness.path.clone();
        let original_expiry = witness.expires;
        let original = witness.durable.clone();
        self.read_checked("require_human_snapshot",Some(deadline),move|connection,check|{
            let tx=connection.unchecked_transaction()?;
            check.now()?;
            let config:Option<String>=tx.query_row("SELECT value FROM meta WHERE key='config_generation'",[],|r|r.get(0)).optional()?;
            if config.and_then(|s|s.parse::<u64>().ok())!=Some(generation) {return Err(refused());}
            let sql=format!("SELECT {}, {}, u.status,u.authz_version,u.groups,o.revision,a.realm FROM session_handles h JOIN sessions s ON s.session_id=h.session_id JOIN users u ON u.user_id=s.user_id JOIN providers p ON p.provider_id=s.provider_id AND p.enabled=1 AND p.deleted_at IS NULL JOIN human_provider_owners o ON o.provider_id=p.provider_id JOIN human_user_ids i ON i.user_id=u.user_id JOIN human_authority_realm a ON a.singleton=1 WHERE h.handle_sha256=?1 AND h.host=?2 AND length(s.factors)<=65536 AND length(s.snapshot)<=65536 AND length(u.groups)<=65536",cols("h",HANDLE_COLS),cols("s",SESSION_COLS));
            let hn=HANDLE_COLS.len();let sn=SESSION_COLS.len();
            let found=tx.query_row(&sql,params![blob(&expected.handle.handle_sha256),expected.handle.host.as_str()],|r|Ok((||->StoreResult<_>{Ok((HandleView{handle:rows::handle(r,0)?,session:rows::session(r,hn)?,user:rows::user_authz(r,hn+sn)?},r.get::<_,i64>(hn+sn+3)?,r.get::<_,String>(hn+sn+4)?))})())).optional()?.transpose()?.ok_or_else(refused)?;
            let (current,provider_revision,realm)=found;
            if !super::identity_owner::valid_realm(&realm) {return Err(refused());}
            if provider_revision!=revision || !same(&current,&expected) || current.handle.issued_aal>current.session.aal || current.handle.created_at>now || current.session.created_at>now || current.session.auth_time>now || now>=original_expiry {return Err(refused());}
            if !matches!(lifetimes::evaluate(&current.handle,&current.session,&app.session,&policy,now),LifetimeVerdict::Live{..}) {return Err(refused());}
            // Native TOTP provenance is mandatory for handle AAL2. Only this
            // establishing factor may satisfy its freshness; newer unsupported
            // factors cannot freshen an older TOTP.
            let primary=super::primary_owner::current(&tx,&current.session,revision,generation,&material)?;
            let mut establishing=None;
            let factors=if current.handle.issued_aal==Aal::Two {
                let factor=super::totp_owner::current(&tx,current.session.session_id.as_str())?;
                if factor.at_ms>now.0 {return Err(refused());}
                let at=factor.at_ms;
                establishing=Some(factor);
                vec![crate::session::FactorEntry{kind:crate::session::FactorKind::Totp,provider:None,at:Timestamp(at)}]
            } else {vec![]};
            if step_up::evaluate(&app.step_up,&path,current.handle.issued_aal,current.session.auth_time,&factors,now)!=step_up::StepUpVerdict::NotRequired {return Err(refused());}
            if let Some(age)=app.max_auth_age && now.since(current.session.auth_time)>age {return Err(refused());}
            let mut expires=original_expiry;
            for rule in app.step_up.iter().filter(|rule|step_up::rule_matches(rule,&path)) {
                if let Some(age)=rule.max_age {
                    let at=if rule.aal==Aal::Two {Timestamp(establishing.as_ref().ok_or_else(refused)?.at_ms)} else {current.session.auth_time};
                    expires=expires.min(at.add(age));
                }
            }
            if let Some(age)=app.max_auth_age {expires=expires.min(current.session.auth_time.add(age));}
            let result=Current{realm,factor:establishing,primary,expires};
            if now>=expires || original.as_ref().is_some_and(|expected|expected!=&result) {return Err(refused());}
            check.now()?;tx.commit()?;Ok(result)
        }).await
    }
}

impl Current {
    /// Stable account coordinate only; never a receipt or authentication grant.
    pub(crate) fn subject_for_witness(
        &self,
        issuer: &str,
        witness: &Witness,
    ) -> StoreResult<String> {
        use sha2::{Digest as _, Sha256};
        let user = witness.view.session.user_id.as_str();
        if issuer.is_empty()
            || issuer.len() > 128
            || !issuer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || user.is_empty()
            || user.len() > 256
            || user.chars().any(char::is_control)
            || self.realm.len() != 64
            || !self
                .realm
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refused());
        }
        let realm = data_encoding::HEXLOWER
            .decode(self.realm.as_bytes())
            .map_err(|_| refused())?;
        if realm.len() != 32 || realm.iter().all(|b| *b == 0) {
            return Err(refused());
        }
        let mut hash = Sha256::new();
        hash.update(b"hopae:native-human-subject:v1\0");
        for value in [issuer.as_bytes(), realm.as_slice(), user.as_bytes()] {
            hash.update(
                u32::try_from(value.len())
                    .map_err(|_| refused())?
                    .to_be_bytes(),
            );
            hash.update(value);
        }
        Ok(format!(
            "human1:{}",
            data_encoding::HEXLOWER.encode(&hash.finalize())
        ))
    }
}

impl Current {
    #[allow(dead_code)] // Used by the additive native Human retained-record quota.
    pub(crate) fn owned_heap_bytes(&self) -> StoreResult<usize> {
        crate::store::types::heap_sum([
            self.realm.capacity(),
            self.primary.owned_heap_bytes()?,
            self.factor
                .as_ref()
                .map_or(Ok(0), |factor| factor.owned_heap_bytes())?,
        ])
    }
}
