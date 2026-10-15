//! Single-owner publication worker primitive; request reads use immutable snapshots.
use super::{publication, runtime};
use arc_swap::ArcSwap;
use rusqlite::Connection;
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
    pub(crate) verified_started: std::time::Instant,
}
impl ServiceAuthentication {
    pub fn revision(&self) -> u64 {
        self.revision
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
        if !(1..=9_007_199_254_740_991).contains(&self.revision) {
            return Err(runtime::Error::Unavailable);
        }
        if !self.available() {
            return Err(runtime::Error::Unavailable);
        }
        let runtime = self.runtime.as_ref().ok_or(runtime::Error::Unavailable)?;
        let begun = std::time::Instant::now();
        let evidence = runtime
            .authenticate_async(host, port, token, ip, now)
            .await?;
        let verified_started = std::time::Instant::now();
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
        Ok(ServiceAuthentication {
            evidence,
            revision: self.revision,
            verified_ms,
            verified_started,
        })
    }
}
pub struct Authorization<'a> {
    pub actor: &'a str,
    pub guard: &'a dyn Fn(&Connection) -> Result<(), publication::Error>,
}
pub struct Authority {
    observed_time: Arc<std::sync::atomic::AtomicU64>,
    snapshot: Arc<ArcSwap<Snapshot>>,
}
impl Authority {
    /// Load durable state before readiness. Bootstrap is imported only if no durable row exists.
    /// Application-scope validation must be supplied by the authenticated owner.
    pub fn load(
        connection: &mut Connection,
        bootstrap: Option<runtime::Config>,
        env: &dyn Fn(&str) -> Option<String>,
        validate: &dyn Fn(&runtime::Config) -> Result<(), publication::Error>,
    ) -> Result<Self, publication::Error> {
        let document = publication::read(connection)?;
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
    pub fn publish(
        &mut self,
        connection: &mut Connection,
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
    pub fn publish_authorized(
        &mut self,
        connection: &mut Connection,
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
