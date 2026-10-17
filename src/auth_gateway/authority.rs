//! Single-owner publication worker primitive; request reads use immutable snapshots.
use super::{publication, runtime};
use crate::store::meta::{MetaDb, MetaTx};
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct Snapshot {
    pub(crate) publication: Arc<std::sync::atomic::AtomicBool>,
    pub revision: u64,
    pub runtime: Option<runtime::Runtime>,
}
/// Native profile-owned authentication. No caller-supplied revision or assurance.
pub struct ServiceAuthentication {
    pub(crate) evidence: super::VerifiedEvidence,
    pub(crate) revision: u64,
    pub(crate) verified_ms: u64,
    observed: Option<ObservedBudget>,
}
struct ObservedBudget {
    verified_ms: u64,
    started: hangang_runtime::time::ElapsedStamp,
}
fn observed_completion(start_ms: u64, floor_ms: u64, elapsed: std::time::Duration) -> Option<u64> {
    let elapsed_ms = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000)).ok()?;
    let now = start_ms.checked_add(elapsed_ms)?.max(floor_ms);
    (1..=9_007_199_254_740_991).contains(&now).then_some(now)
}
fn observed_remaining(
    verified_ms: u64,
    expires_ms: u64,
    wall_ms: u64,
    elapsed: std::time::Duration,
) -> Option<u64> {
    let age_ms = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000)).ok()?;
    let original = expires_ms.checked_sub(verified_ms)?.min(1000);
    let remaining = original
        .checked_sub(age_ms)?
        .min(expires_ms.checked_sub(wall_ms.max(verified_ms))?);
    (remaining > 0).then_some(remaining)
}
impl ServiceAuthentication {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn observed_remaining_ms(&self, wall_ms: u64) -> Option<u64> {
        let budget = self.observed.as_ref()?;
        observed_remaining(
            budget.verified_ms,
            self.evidence.expires_at,
            wall_ms,
            budget.started.elapsed().ok()?,
        )
    }
}
impl Snapshot {
    pub fn available(&self) -> bool {
        !self.publication.load(std::sync::atomic::Ordering::Acquire)
    }
    pub async fn authenticate_for_receipt(
        &self,
        host: &str,
        port: u16,
        token: Option<&str>,
        ip: std::net::IpAddr,
        now: u64,
    ) -> Result<ServiceAuthentication, runtime::Error> {
        self.authenticate_credential_for_receipt(
            host,
            port,
            token.map(super::composition::Credential::Bearer),
            ip,
            now,
            None,
        )
        .await
    }
    pub(crate) async fn authenticate_credential_for_receipt(
        &self,
        host: &str,
        port: u16,
        token: Option<super::composition::Credential<'_>>,
        ip: std::net::IpAddr,
        now: u64,
        entry_stamp: Option<&super::composition::EntryTime<'_>>,
    ) -> Result<ServiceAuthentication, runtime::Error> {
        if !(1..=9_007_199_254_740_991).contains(&self.revision) {
            return Err(runtime::Error::Unavailable);
        }
        if !self.available() {
            return Err(runtime::Error::Unavailable);
        }
        let runtime = self.runtime.as_ref().ok_or(runtime::Error::Unavailable)?;
        // Optional only for legacy compatibility on unsupported platforms. The
        // observed contract never falls back to Instant or a fresh age origin.
        let observed_start = hangang_runtime::time::ElapsedStamp::now().ok();
        let begun = std::time::Instant::now();
        let evidence = runtime
            .authenticate_credential_async(host, port, token, ip, now, entry_stamp)
            .await?;
        // Capture completion age before sampling pre-await elapsed: a pause
        // between them is charged conservatively rather than lost on reset.
        let completion_stamp = hangang_runtime::time::ElapsedStamp::now().ok();
        let verified_ms = runtime
            .observed_time
            .load(std::sync::atomic::Ordering::Acquire)
            .max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        if !self.available() {
            return Err(runtime::Error::Unavailable);
        }
        if evidence.expires_at <= verified_ms {
            return Err(runtime::Error::Expired);
        }
        let observed = observed_start.and_then(|start| {
            let started = completion_stamp?;
            let elapsed = start.elapsed().ok()?;
            let observed_ms = observed_completion(now, verified_ms, elapsed)?;
            (observed_ms < evidence.expires_at).then_some(ObservedBudget {
                verified_ms: observed_ms,
                started,
            })
        });
        Ok(ServiceAuthentication {
            evidence,
            revision: self.revision,
            verified_ms,
            observed,
        })
    }
}
pub struct Authorization<'a> {
    pub actor: &'a str,
    pub guard: &'a dyn Fn(&dyn MetaTx) -> Result<(), publication::Error>,
}
pub struct Authority {
    observed_time: Arc<std::sync::atomic::AtomicU64>,
    snapshot: Arc<ArcSwap<Snapshot>>,
}
impl Authority {
    /// Load durable state before readiness. Bootstrap is imported only if no durable row exists.
    /// Application-scope validation must be supplied by the authenticated owner.
    pub fn load<D: MetaDb>(
        connection: &mut D,
        bootstrap: Option<runtime::Config>,
        env: &dyn Fn(&str) -> Option<String>,
        validate: &dyn Fn(&runtime::Config) -> Result<(), publication::Error>,
    ) -> Result<Self, publication::Error> {
        let document = connection.meta_read(|tx| publication::read(tx))?;
        let configuration = document
            .as_ref()
            .map_or(bootstrap.as_ref(), |d| d.configuration.as_ref());
        let runtime = Self::compile(configuration, env, validate)?;
        let revision = if let Some(document) = document {
            document.revision
        } else {
            publication::publish(connection, 0, bootstrap, "bootstrap")?.revision
        };
        let observed_time = runtime
            .as_ref()
            .map(|runtime| runtime.observed_time.clone())
            .unwrap_or_default();
        Ok(Self {
            observed_time,
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot {
                publication: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                revision,
                runtime,
            })),
        })
    }
    fn compile(
        configuration: Option<&runtime::Config>,
        env: &dyn Fn(&str) -> Option<String>,
        validate: &dyn Fn(&runtime::Config) -> Result<(), publication::Error>,
    ) -> Result<Option<runtime::Runtime>, publication::Error> {
        configuration
            .map(|config| {
                validate(config)?;
                runtime::Runtime::compile(config, env).map_err(|_| publication::Error::Invalid)
            })
            .transpose()
    }
    /// Run synchronously inside the exclusive blocking publication worker.
    /// No await or fallible operation separates commit from snapshot installation.
    pub fn publish<D: MetaDb>(
        &mut self,
        connection: &mut D,
        expected: u64,
        configuration: Option<runtime::Config>,
        actor: &str,
        env: &dyn Fn(&str) -> Option<String>,
        validate: &dyn Fn(&runtime::Config) -> Result<(), publication::Error>,
    ) -> Result<publication::Document, publication::Error> {
        self.publish_authorized(
            connection,
            expected,
            configuration,
            Authorization {
                actor,
                guard: &|_| Ok(()),
            },
            env,
            validate,
        )
    }
    pub fn publish_authorized<D: MetaDb>(
        &mut self,
        connection: &mut D,
        expected: u64,
        configuration: Option<runtime::Config>,
        authorization: Authorization<'_>,
        env: &dyn Fn(&str) -> Option<String>,
        validate: &dyn Fn(&runtime::Config) -> Result<(), publication::Error>,
    ) -> Result<publication::Document, publication::Error> {
        if self.snapshot.load().revision != expected {
            return Err(publication::Error::Conflict);
        }
        let previous = self.snapshot.load_full();
        let mut runtime = configuration
            .as_ref()
            .map(|config| {
                validate(config)?;
                runtime::Runtime::compile_resuming(config, env, previous.runtime.as_ref())
                    .map_err(|_| publication::Error::Invalid)
            })
            .transpose()?;
        if let Some(runtime) = &mut runtime {
            runtime.observed_time = self.observed_time.clone();
        }
        let prepared = Arc::new(Snapshot {
            publication: previous.publication.clone(),
            revision: expected.checked_add(1).ok_or(publication::Error::Invalid)?,
            runtime,
        });
        previous
            .publication
            .store(true, std::sync::atomic::Ordering::Release);
        let result = publication::publish_guarded(
            connection,
            expected,
            configuration,
            authorization.actor,
            authorization.guard,
        );
        let document = match result {
            Ok(document) => document,
            Err(error) => {
                previous
                    .publication
                    .store(false, std::sync::atomic::Ordering::Release);
                return Err(error);
            }
        };
        self.snapshot.store(prepared);
        previous
            .publication
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(document)
    }
    pub fn reader(&self) -> Arc<ArcSwap<Snapshot>> {
        self.snapshot.clone()
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }
}
#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    #[test]
    fn observed_completion_charges_pre_auth_suspend_before_starting_a_new_budget() {
        use std::time::Duration;
        let suspended = super::observed_completion(10_000, 10_000, Duration::from_secs(2)).unwrap();
        assert_eq!(suspended, 12_000);
        assert_eq!(
            super::observed_remaining(suspended, 11_000, 10_000, Duration::ZERO),
            None
        );
        // A post-await stamp alone would have incorrectly renewed this proof.
        assert_eq!(
            super::observed_remaining(10_000, 11_000, 10_000, Duration::ZERO),
            Some(1000)
        );
        assert_eq!(
            super::observed_completion(10_000, 10_050, Duration::from_nanos(1)),
            Some(10_050)
        );
        assert_eq!(
            super::observed_completion(10_000, 10_000, Duration::from_nanos(1)),
            Some(10_001)
        );
    }

    #[test]
    fn observed_original_budget_cannot_renew_through_suspend_rollback_or_rounding() {
        use std::time::Duration;
        for (age, expected) in [
            (Duration::ZERO, Some(1000)),
            (Duration::from_nanos(1), Some(999)),
            (Duration::from_millis(999), Some(1)),
            (Duration::from_nanos(999_000_001), None),
            (Duration::from_millis(1000), None),
            (Duration::from_secs(2), None),
        ] {
            for wall in [1, 9000, 10_000] {
                assert_eq!(
                    super::observed_remaining(10_000, 11_000, wall, age),
                    expected
                );
            }
        }
        assert_eq!(
            super::observed_remaining(10_000, 11_000, 10_700, Duration::from_millis(100)),
            Some(300)
        );
        assert_eq!(
            super::observed_remaining(10_000, 11_000, 11_000, Duration::ZERO),
            None
        );
    }

    #[test]
    fn observed_native_budget_overflow_and_invalid_lifetime_refuse() {
        use std::time::Duration;
        assert_eq!(
            super::observed_completion(u64::MAX, 1, Duration::from_nanos(1)),
            None
        );
        assert_eq!(
            super::observed_completion(9_007_199_254_740_991, 1, Duration::from_nanos(1)),
            None
        );
        assert_eq!(super::observed_completion(1, 1, Duration::MAX), None);
        assert_eq!(
            super::observed_remaining(1000, 999, 1000, Duration::ZERO),
            None
        );
        assert_eq!(
            super::observed_remaining(1000, 2000, 1000, Duration::MAX),
            None
        );
    }
    use super::*;
    fn config() -> runtime::Config {
        serde_json::from_value(serde_json::json!({"authority_id":"owned","profiles":[{
            "service_id":"orders","host":"app.example.test","ports":[443],"realm":"services",
            "api_keys":[{"token_env":"OWNED_KEY","subject":"worker"}]}]}))
        .unwrap()
    }
    #[test]
    fn observed_expiration_floor_survives_disable_and_reenable() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
            .unwrap();
        let key = "owned-key-at-least-thirty-two-bytes-long";
        let env = |_: &str| Some(key.to_owned());
        let validate = |_: &runtime::Config| Ok(());
        let mut profile = config();
        profile.profiles[0].api_keys[0].expires_at = Some(1000);
        let mut authority =
            Authority::load(&mut db, Some(profile.clone()), &env, &validate).unwrap();
        let old = authority.snapshot();
        let ip = "127.0.0.1".parse().unwrap();
        assert_eq!(
            old.runtime
                .as_ref()
                .unwrap()
                .authenticate("app.example.test", 443, Some(key), ip, 1001)
                .unwrap_err(),
            runtime::Error::Expired
        );
        authority
            .publish(&mut db, 1, None, "admin", &env, &validate)
            .unwrap();
        authority
            .publish(&mut db, 2, Some(profile), "admin", &env, &validate)
            .unwrap();
        assert_eq!(
            authority
                .snapshot()
                .runtime
                .as_ref()
                .unwrap()
                .authenticate("app.example.test", 443, Some(key), ip, 1)
                .unwrap_err(),
            runtime::Error::Expired
        );
    }
    #[test]
    fn missing_secret_does_not_publish_and_tombstone_overrides_bootstrap() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
            .unwrap();
        let env = |_: &str| Some("owned-key-at-least-thirty-two-bytes-long".into());
        let validate = |_: &runtime::Config| Ok(());
        let mut authority = Authority::load(&mut db, Some(config()), &env, &validate).unwrap();
        let reader = authority.reader();
        let old = authority.snapshot();
        assert!(old.runtime.is_some());
        assert!(matches!(
            authority.publish(&mut db, 1, Some(config()), "admin", &|_| None, &validate),
            Err(publication::Error::Invalid)
        ));
        assert_eq!(publication::read(&db).unwrap().unwrap().revision, 1);
        authority
            .publish(&mut db, 1, None, "admin", &env, &validate)
            .unwrap();
        assert_eq!(reader.load().revision, 2);
        assert_eq!(authority.snapshot().revision, 2);
        assert!(authority.snapshot().runtime.is_none());
        // Existing readers retain their immutable snapshot; stream generation checking is still required.
        assert_eq!(old.revision, 1);
        let restarted = Authority::load(&mut db, Some(config()), &env, &validate).unwrap();
        assert_eq!(restarted.snapshot().revision, 2);
        assert!(restarted.snapshot().runtime.is_none());
    }
    #[test]
    fn application_scope_rejection_does_not_seed_database() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT")
            .unwrap();
        let result = Authority::load(
            &mut db,
            Some(config()),
            &|_| Some("owned-key-at-least-thirty-two-bytes-long".into()),
            &|_| Err(publication::Error::Invalid),
        );
        assert!(matches!(result, Err(publication::Error::Invalid)));
        assert!(publication::read(&db).unwrap().is_none());
    }
    #[test]
    fn publication_fence_covers_transaction_and_failed_write_restores_old_reader() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        let mut owner = Authority::load(
            &mut db,
            Some(config()),
            &|_| Some("owned-credential-at-least-thirty-two-bytes".into()),
            &|_| Ok(()),
        )
        .unwrap();
        let old = owner.snapshot();
        let calls = std::cell::Cell::new(0);
        assert!(
            owner
                .publish_authorized(
                    &mut db,
                    1,
                    None,
                    Authorization {
                        actor: "operator",
                        guard: &|_| {
                            assert!(!old.available());
                            calls.set(calls.get() + 1);
                            if calls.get() == 2 {
                                Err(publication::Error::Denied)
                            } else {
                                Ok(())
                            }
                        }
                    },
                    &|_| None,
                    &|_| Ok(())
                )
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert!(old.available());
        assert!(Arc::ptr_eq(&old, &owner.snapshot()));
        assert_eq!(publication::read(&db).unwrap().unwrap().revision, 1);
        owner
            .publish_authorized(
                &mut db,
                1,
                None,
                Authorization {
                    actor: "operator",
                    guard: &|_| {
                        assert!(!old.available());
                        Ok(())
                    },
                },
                &|_| None,
                &|_| Ok(()),
            )
            .unwrap();
        assert!(owner.snapshot().available());
        assert!(!Arc::ptr_eq(&old, &owner.snapshot()));
        assert_eq!(owner.snapshot().revision, 2);
    }
}
