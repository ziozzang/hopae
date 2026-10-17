//! Live reconciliation of the configuration-authoritative authentication
//! profiles and credential projection plan (`authentication.source = config`).
//!
//! The configuration file is polled (`authentication.reload_interval_ms`,
//! default 1 s; no file-system notifications, as a ConfigMap volume swaps a
//! symlink) by content digest. A changed file is read, parsed and validated
//! completely, its referenced environment variables checked and its profiles
//! compiled, exactly as a start would; only then is the store reconciled
//! through the same CAS publication a start uses (next revision, audit row
//! with actor `config`, `authentication.reconciled` with `cause = reload`) and
//! the live snapshot swapped, so a revoked key or a removed profile stops
//! authenticating at once. An invalid file changes nothing: the current
//! profiles stay in force, `hopae_config_reload_failing` is `1`, a warning is
//! logged and `/v1/status` shows the error until a valid file arrives.
//! Changes to any other key still need a restart: they are reported
//! (`result = restart_required`) and otherwise ignored.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::app::Services;
use crate::config::{AuthenticationSource, Config};
use crate::event::types::{EventKind, Outcome};
use crate::telemetry::counters;

/// Reconciliations by result: `reconciled`, `invalid`, `restart_required`.
pub const CONFIG_RELOADS_TOTAL: &str = "hopae_config_reloads_total";
/// `1` while the newest configuration file is invalid (the previous profiles
/// stay in force); `0` otherwise.
pub const CONFIG_RELOAD_FAILING: &str = "hopae_config_reload_failing";

/// What one poll did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Polled {
    Unchanged,
    /// The file changed; `(kind, previous, revision)` per publication made.
    Reconciled(Vec<(&'static str, u64, u64)>),
    Invalid(String),
}

pub struct Reconciler {
    path: Option<PathBuf>,
    interval: Duration,
    services: Services,
    /// The file Hopae started with, without the reconciled keys.
    baseline: Option<serde_json::Value>,
    digest: Mutex<Option<[u8; 32]>>,
}

/// The file's JSON without the keys reconciled live, for comparison.
fn rest_of(text: &[u8]) -> Option<serde_json::Value> {
    let mut v: serde_json::Value = serde_json::from_slice(text).ok()?;
    let o = v.as_object_mut()?;
    o.remove("authentication_gateway");
    o.remove("credential_projection");
    Some(v)
}

impl Reconciler {
    pub fn new(services: &Services) -> Reconciler {
        let cfg = &services.config;
        Reconciler {
            path: cfg.source_path.clone(),
            interval: cfg.auth_reload_interval().unwrap_or(Duration::from_secs(1)),
            services: services.clone(),
            baseline: cfg
                .source_path
                .as_ref()
                .and_then(|p| std::fs::read(p).ok())
                .and_then(|b| rest_of(&b)),
            digest: Mutex::new(None),
        }
    }

    fn report(&self, polled: &Polled, restart_required: bool) {
        let status = &self.services.reload_status;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let profiles = self
            .services
            .authentication_authority
            .as_ref()
            .and_then(|a| a.lock().ok().map(|a| a.snapshot().revision));
        let projections = self
            .services
            .projection_authority
            .lock()
            .ok()
            .map(|o| o.reader().load().revision());
        let (failing, error) = match polled {
            Polled::Invalid(e) => (true, Some(e.clone())),
            _ => (false, None),
        };
        let mut value = json!({
            "source": "config",
            "interval_ms": self.interval.as_millis() as u64,
            "failing": failing,
            "error": error,
            "restart_required": restart_required,
            "profiles_revision": profiles,
            "projections_revision": projections,
            "last_change_at": now,
        });
        if let Polled::Reconciled(done) = polled {
            value["last_reconciled_at"] = json!(now);
            value["reconciled"] = json!(
                done.iter()
                    .map(|(k, p, r)| json!({"kind": k, "previous_revision": p, "revision": r}))
                    .collect::<Vec<_>>()
            );
        }
        status.set_config(value);
    }

    /// Re-read the file; reconcile when it changed and is valid.
    pub fn poll(&self) -> Polled {
        let Some(path) = &self.path else {
            return Polled::Unchanged;
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return self.fail(format!("unreadable: {e}")),
        };
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        {
            let last = self.digest.lock().unwrap_or_else(|p| p.into_inner());
            if *last == Some(digest) {
                return Polled::Unchanged;
            }
        }
        let polled = self.apply(path, &bytes);
        if !matches!(polled, Polled::Invalid(_)) {
            *self.digest.lock().unwrap_or_else(|p| p.into_inner()) = Some(digest);
        }
        polled
    }

    fn fail(&self, why: String) -> Polled {
        counters::inc(CONFIG_RELOADS_TOTAL, &[("result", "invalid")]);
        counters::set(CONFIG_RELOAD_FAILING, &[], 1);
        tracing::warn!(error = %why, "the changed configuration file is invalid; the current authentication profiles stay in force");
        let polled = Polled::Invalid(why);
        self.report(&polled, false);
        polled
    }

    fn apply(&self, path: &std::path::Path, bytes: &[u8]) -> Polled {
        let cfg = match crate::config::load(path) {
            Ok(c) => c,
            Err(e) => return self.fail(e.to_string()),
        };
        let problems = crate::config::check_env(&cfg, |n| std::env::var(n).ok());
        if !problems.is_empty() {
            return self.fail(problems.join("; "));
        }
        let restart_required = cfg.authentication.source != AuthenticationSource::Config
            || (self.baseline.is_some() && rest_of(bytes) != self.baseline);
        if restart_required {
            counters::inc(CONFIG_RELOADS_TOTAL, &[("result", "restart_required")]);
            tracing::warn!(
                "the configuration file changed keys other than the authentication profiles and the credential projection; those changes apply at the next restart"
            );
        }
        if cfg.authentication.source != AuthenticationSource::Config {
            counters::set(CONFIG_RELOAD_FAILING, &[], 0);
            let polled = Polled::Reconciled(Vec::new());
            self.report(&polled, true);
            return polled;
        }
        let mut done = Vec::new();
        match self.profiles(&cfg) {
            Ok(Some(d)) => done.push(d),
            Ok(None) => {}
            Err(e) => return self.fail(e),
        }
        match self.projections(&cfg) {
            Ok(Some(d)) => done.push(d),
            Ok(None) => {}
            Err(e) => return self.fail(e),
        }
        counters::set(CONFIG_RELOAD_FAILING, &[], 0);
        if !done.is_empty() {
            counters::inc(CONFIG_RELOADS_TOTAL, &[("result", "reconciled")]);
            for (kind, previous, revision) in &done {
                tracing::info!(kind, previous, revision, "configuration reconciled live");
            }
            self.record(&done);
        }
        let polled = Polled::Reconciled(done);
        self.report(&polled, restart_required);
        polled
    }

    /// The profiles: publish the file's document when it differs.
    fn profiles(&self, cfg: &Config) -> Result<Option<(&'static str, u64, u64)>, String> {
        let Some(owner) = &self.services.authentication_authority else {
            return if cfg.authentication_gateway.is_some() {
                Err("authentication profiles appeared in the file; they need a restart to start the authentication gateway".into())
            } else {
                Ok(None)
            };
        };
        use crate::store::meta::MetaDb as _;
        let mut connection = self.services.store.meta();
        let validate = |profiles: &crate::auth_gateway::runtime::Config| {
            let mut candidate = cfg.clone();
            candidate.authentication_gateway = Some(profiles.clone());
            candidate
                .validate()
                .map_err(|_| crate::auth_gateway::publication::Error::Invalid)
        };
        let env = |name: &str| std::env::var(name).ok();
        let mut owner = owner
            .lock()
            .map_err(|_| "the authentication profile owner is unavailable".to_string())?;
        // Several replicas reconcile the same file: whoever publishes first
        // wins, the others find the store already equal (ADR-0020 slice 5).
        for _ in 0..3 {
            let durable = connection
                .meta_read(|tx| crate::auth_gateway::publication::read(tx))
                .map_err(|_| "the stored authentication profiles are unreadable".to_string())?;
            let same = match &durable {
                Some(d) => {
                    serde_json::to_value(&d.configuration).ok()
                        == serde_json::to_value(&cfg.authentication_gateway).ok()
                }
                None => cfg.authentication_gateway.is_none(),
            };
            if same {
                // Another replica's publication: follow it at once.
                let _ = owner.refresh(&mut connection, &env, &validate);
                return Ok(None);
            }
            let previous = durable.as_ref().map_or(0, |d| d.revision);
            let _ = owner.refresh(&mut connection, &env, &validate);
            match owner.publish(
                &mut connection,
                previous,
                cfg.authentication_gateway.clone(),
                "config",
                &env,
                &validate,
            ) {
                Ok(document) => return Ok(Some(("profiles", previous, document.revision))),
                Err(crate::auth_gateway::publication::Error::Conflict) => continue,
                Err(e) => {
                    return Err(format!(
                        "the configured authentication profiles were refused: {e:?}"
                    ));
                }
            }
        }
        Err("the authentication profiles kept changing concurrently; retrying".into())
    }

    /// The projection plan, compared by its plans and published at the
    /// store's next revision (as a start does).
    fn projections(&self, cfg: &Config) -> Result<Option<(&'static str, u64, u64)>, String> {
        use crate::store::meta::MetaDb as _;
        let mut connection = self.services.store.meta();
        let plans = |c: &Option<crate::auth_gateway::projection::Configuration>| {
            serde_json::to_value(c.as_ref().map(|c| &c.plans)).ok()
        };
        let mut owner = self
            .services
            .projection_authority
            .lock()
            .map_err(|_| "the credential projection owner is unavailable".to_string())?;
        let accept = |_: &crate::auth_gateway::projection::Configuration| Ok(());
        // As the profiles: concurrent replicas converge on one publication.
        for _ in 0..3 {
            let durable = connection
                .meta_read(|tx| crate::auth_gateway::projection_authority::read(tx))
                .map_err(|_| "the stored credential projection is unreadable".to_string())?;
            let current = durable.as_ref().and_then(|d| d.configuration.clone());
            let same = match &durable {
                Some(_) => plans(&current) == plans(&cfg.credential_projection),
                None => cfg.credential_projection.is_none(),
            };
            // The file is authoritative: its plans are the capabilities.
            let _ = owner.refresh(&mut connection, &accept);
            if same {
                return Ok(None);
            }
            let previous = durable.as_ref().map_or(0, |d| d.revision);
            let mut desired = cfg.credential_projection.clone();
            if let Some(d) = &mut desired {
                d.revision = previous + 1;
            }
            match owner.publish(&mut connection, previous, desired, "config", &|_| Ok(())) {
                Ok(document) => return Ok(Some(("projections", previous, document.revision))),
                Err(_) => {
                    // A concurrent publication moved the revision, or the
                    // plans are refused: re-read before deciding.
                    let moved = connection
                        .meta_read(|tx| crate::auth_gateway::projection_authority::read(tx))
                        .ok()
                        .flatten()
                        .map_or(0, |d| d.revision);
                    if moved == previous {
                        return Err("the configured credential projection was refused".into());
                    }
                }
            }
        }
        Err("the credential projection kept changing concurrently; retrying".into())
    }

    fn record(&self, done: &[(&'static str, u64, u64)]) {
        let events: Vec<_> = done
            .iter()
            .map(|(kind, previous, revision)| {
                self.services.emitter.required(
                    EventKind::AuthenticationReconciled,
                    Outcome::Success,
                    "reload",
                    |b| {
                        b.attr("kind", *kind)
                            .attr("previous_revision", *previous)
                            .attr("revision", *revision)
                            .attr("actor", "config")
                            .attr("cause", "reload")
                    },
                )
            })
            .collect();
        let store = self.services.store.clone();
        // The publications are committed; the record follows on the runtime.
        tokio::runtime::Handle::current().spawn(async move {
            if let Err(e) = store.events().append_required(events).await {
                tracing::error!(error = %e, "authentication.reconciled could not be recorded");
            }
        });
    }

    /// Poll every interval until `stop` turns true (file and store work on
    /// the blocking pool).
    pub async fn run(self, interval: Duration, mut stop: tokio::sync::watch::Receiver<bool>) {
        let me = Arc::new(self);
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let r = me.clone();
                    let handle = tokio::runtime::Handle::current();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _guard = handle.enter();
                        r.poll()
                    })
                    .await;
                }
                _ = async { let _ = stop.wait_for(|s| *s).await; } => return,
            }
        }
    }
}
