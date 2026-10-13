//! Single-owner publication worker primitive; request reads use immutable snapshots.
use super::{publication, runtime};
use arc_swap::ArcSwap;
use rusqlite::Connection;
use std::sync::Arc;

pub struct Snapshot {
    pub revision: u64,
    pub runtime: Option<runtime::Runtime>,
}
pub struct Authorization<'a> {
    pub actor: &'a str,
    pub guard: &'a dyn Fn(&Connection) -> Result<(), publication::Error>,
}
pub struct Authority {
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
        Ok(Self {
            snapshot: Arc::new(ArcSwap::from_pointee(Snapshot { revision, runtime })),
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
        let runtime = Self::compile(configuration.as_ref(), env, validate)?;
        let document = publication::publish_guarded(
            connection,
            expected,
            configuration,
            authorization.actor,
            authorization.guard,
        )?;
        self.snapshot.store(Arc::new(Snapshot {
            revision: document.revision,
            runtime,
        }));
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
}
