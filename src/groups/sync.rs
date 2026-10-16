//! Group sync and maintenance: applying a provider's assertion at sign-in,
//! the bounded periodic LDAP refresh, and the maintenance pass (expiry,
//! removal grace, stale provider groups, journal retention).
//!
//! A sync never blocks a sign-in: a refused or failed sync leaves the
//! person's previous memberships as they were and is reported as a
//! `group.sync_refused` diagnostic event.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::Source;
use super::config::{GroupsConfig, ProviderGroups, Refusal};
use super::projection::ProjectionSigner;
use crate::crypto::{Clock, Rng};
use crate::event::bus::Emitter;
use crate::event::types::{Event, EventBuilder, EventKind, Outcome};
use crate::identity::types::UserId;
use crate::provider::ProviderKind;
use crate::provider::types::{ProviderId, RawGroup};
use crate::store::sqlite::Store;
use crate::store::sqlite::groups::{MaintenanceReport, SyncReport, WritePolicy};
use crate::store::types::ProviderRow;
use crate::store::{Deadline, Directory};

/// Deadline of one sync or maintenance store call.
const STORE_BUDGET: Duration = Duration::from_secs(5);

/// The groups service shared by the portal flows, the console and the
/// maintenance worker.
pub struct GroupService {
    pub store: Store,
    pub cfg: GroupsConfig,
    pub signer: Option<Arc<ProjectionSigner>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    emitter: Option<Emitter>,
}

impl std::fmt::Debug for GroupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupService")
            .field("projection", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

/// What a provider assertion did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The provider does not sync groups, or the assertion carried none.
    NotAsserted,
    Applied(SyncReport),
    /// Nothing changed; the reason is a stable code.
    Refused(&'static str),
}

impl GroupService {
    pub fn new(
        store: Store,
        cfg: GroupsConfig,
        signer: Option<Arc<ProjectionSigner>>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        emitter: Option<Emitter>,
    ) -> GroupService {
        GroupService {
            store,
            cfg,
            signer,
            clock,
            rng,
            emitter,
        }
    }

    pub fn policy(&self) -> WritePolicy {
        WritePolicy {
            max_groups_per_user: self.cfg.max_groups_per_user,
            gateway_header: self.cfg.gateway_header,
        }
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The event every change of an automatic write is built from.
    fn template(&self, request_id: &str, cause: &'static str) -> Event {
        EventBuilder::new(
            self.clock.as_ref(),
            self.rng.as_ref(),
            EventKind::GroupMemberAdded,
            Outcome::Success,
            request_id,
        )
        .attr("cause", cause)
        .build()
    }

    fn refused(
        &self,
        provider: &ProviderId,
        user: Option<&UserId>,
        request_id: &str,
        why: &'static str,
    ) {
        tracing::warn!(provider = %provider, reason = why, "group sync not applied");
        if let Some(em) = &self.emitter {
            em.diagnostic(
                EventKind::GroupSyncRefused,
                Outcome::Failure,
                request_id,
                |b| {
                    let b = b.provider(provider).attr("cause", why);
                    match user {
                        Some(u) => b.user(u),
                        None => b,
                    }
                },
            );
        }
    }

    /// Apply `raw` (a provider's complete assertion for `user`) under the
    /// rules of the stored provider `row`.
    pub async fn apply(
        &self,
        row: &ProviderRow,
        user: &UserId,
        raw: Option<&[RawGroup]>,
        request_id: &str,
        cause: &'static str,
    ) -> Applied {
        let (Some(spec), Some(raw)) = (ProviderGroups::of_row(&row.config), raw) else {
            return Applied::NotAsserted;
        };
        let Some(rules) = spec.compile() else {
            self.refused(&row.provider_id, Some(user), request_id, "invalid_rules");
            return Applied::Refused("invalid_rules");
        };
        let mapped = match rules.map(raw) {
            Ok(m) => m,
            Err(Refusal::TooMany) => {
                self.refused(
                    &row.provider_id,
                    Some(user),
                    request_id,
                    Refusal::TooMany.as_str(),
                );
                return Applied::Refused(Refusal::TooMany.as_str());
            }
        };
        let source = if row.kind == ProviderKind::Ldap {
            Source::Ldap
        } else {
            Source::Oidc
        };
        match self
            .store
            .groups_sync_user(
                row.provider_id.clone(),
                source,
                user.clone(),
                mapped,
                rules.removal_grace_secs,
                self.policy(),
                self.template(request_id, cause),
                Deadline::after(STORE_BUDGET),
            )
            .await
        {
            Ok(report) => match report.refused {
                Some(why) => {
                    self.refused(&row.provider_id, Some(user), request_id, why);
                    Applied::Refused(why)
                }
                None => Applied::Applied(report),
            },
            Err(e) => {
                tracing::warn!(provider = %row.provider_id, error = %e, "group sync failed");
                self.refused(
                    &row.provider_id,
                    Some(user),
                    request_id,
                    "store_unavailable",
                );
                Applied::Refused("store_unavailable")
            }
        }
    }

    /// One maintenance pass, then one bounded periodic-sync step per LDAP
    /// provider that is due.
    pub async fn maintain(
        &self,
        directory: &dyn Directory,
        lookup: &dyn crate::session::service::ProviderLookup,
    ) -> MaintenanceReport {
        let rows = match directory.providers().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "group maintenance could not read providers");
                return MaintenanceReport::default();
            }
        };
        let grace: HashMap<String, u64> = rows
            .iter()
            .filter_map(|r| {
                let g = ProviderGroups::of_row(&r.config)?;
                Some((r.provider_id.to_string(), g.removal_grace_secs))
            })
            .collect();
        let now = self.clock.now().secs();
        let report = self
            .store
            .groups_maintenance(
                grace,
                now - i64::from(self.cfg.stale_group_days) * 86_400,
                now - i64::from(self.cfg.change_retention_days) * 86_400,
                self.policy(),
                self.template("maintenance", "maintenance"),
                Deadline::after(STORE_BUDGET),
            )
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "group maintenance failed");
                MaintenanceReport::default()
            });
        for row in rows
            .iter()
            .filter(|r| r.kind == ProviderKind::Ldap && r.enabled && r.deleted_at.is_none())
        {
            let Some(spec) = ProviderGroups::of_row(&row.config) else {
                continue;
            };
            let Some(interval) = spec.sync_interval_secs else {
                continue;
            };
            self.sync_step(row, &spec, interval, lookup).await;
        }
        report
    }

    async fn sync_step(
        &self,
        row: &ProviderRow,
        spec: &ProviderGroups,
        interval: u64,
        lookup: &dyn crate::session::service::ProviderLookup,
    ) {
        let Some(provider) = lookup.credential(&row.provider_id) else {
            return;
        };
        let batch = match self
            .store
            .groups_sync_batch(
                row.provider_id.to_string(),
                interval,
                spec.sync_batch,
                Deadline::after(STORE_BUDGET),
            )
            .await
        {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(provider = %row.provider_id, error = %e, "periodic group sync could not start");
                return;
            }
        };
        let mut error = None;
        for (subject, user) in batch {
            match provider.directory_groups(&subject).await {
                Ok(Some(raw)) => {
                    let user = UserId::new(user);
                    self.apply(row, &user, Some(&raw), "group-sync", "periodic_sync")
                        .await;
                }
                Ok(None) => {}
                Err(_) => {
                    // The directory did not answer: stop this step, keep
                    // every membership; the next cycle retries.
                    error = Some("provider_unavailable");
                    self.refused(&row.provider_id, None, "group-sync", "provider_unavailable");
                    break;
                }
            }
        }
        let _ = self
            .store
            .groups_sync_result(
                row.provider_id.to_string(),
                error,
                Deadline::after(STORE_BUDGET),
            )
            .await;
    }

    /// Run [`GroupService::maintain`] every `maintenance_interval_secs`
    /// until `stop` flips to `true`.
    pub async fn run(
        self: Arc<Self>,
        directory: Arc<dyn Directory>,
        lookup: Arc<dyn crate::session::service::ProviderLookup>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let period = Duration::from_secs(self.cfg.maintenance_interval_secs);
        let mut every = crate::event::prune::Every::new(period, self.clock.as_ref());
        loop {
            tokio::select! {
                _ = crate::event::bus::stopped(&mut stop) => break,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    if !every.due(self.clock.as_ref()) {
                        continue;
                    }
                }
            }
            let report = self.maintain(directory.as_ref(), lookup.as_ref()).await;
            if report != MaintenanceReport::default() {
                tracing::info!(?report, "group maintenance");
            }
            every.reset(self.clock.as_ref());
        }
    }
}
