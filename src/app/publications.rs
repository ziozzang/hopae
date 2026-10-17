//! Cross-replica publication following (ADR-0020 slice 5).
//!
//! A profile or projection publication commits through one replica's owner
//! and installs there at once. Every other replica on the same PostgreSQL
//! store follows it: the publishing transaction sends `NOTIFY` on commit,
//! and each follower also polls every [`POLL`], so a missed notification
//! (listener connection dropped, server restart) delays a replica by at
//! most one poll. The follower reloads the durable document under the same
//! owner lock as a local publication and never moves a snapshot backwards.
use std::time::Duration;

use tokio::sync::watch;

use super::Services;

/// The fallback poll period: the bound on how stale a replica can be.
pub const POLL: Duration = Duration::from_secs(1);
/// The pause before reopening a dropped listener connection.
pub const LISTEN_RETRY: Duration = Duration::from_secs(5);

/// What one refresh round installed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Refreshed {
    pub profiles: bool,
    pub projections: bool,
}

/// Reload every published owner snapshot that changed in the store.
/// Blocking: runs on a blocking thread.
pub fn refresh(services: &Services) -> Refreshed {
    let mut out = Refreshed::default();
    let cfg = services.config.clone();
    if let Some(owner) = &services.authentication_authority {
        let validate = |profiles: &crate::auth_gateway::runtime::Config| {
            let mut candidate = (*cfg).clone();
            candidate.authentication_gateway = Some(profiles.clone());
            candidate
                .validate()
                .map_err(|_| crate::auth_gateway::publication::Error::Invalid)
        };
        match owner.lock() {
            Ok(mut owner) => {
                match owner.refresh(
                    &mut services.store.meta(),
                    &|name| std::env::var(name).ok(),
                    &validate,
                ) {
                    Ok(installed) => out.profiles = installed,
                    Err(_) => tracing::warn!("profile publication refresh failed; retrying"),
                }
            }
            Err(_) => tracing::warn!("profile owner unavailable for refresh"),
        }
    }
    let declared = cfg.credential_projection.as_ref();
    match services.projection_authority.lock() {
        Ok(mut owner) => {
            match owner.refresh(&mut services.store.meta(), &|config| {
                crate::auth_gateway::projection::validate_capabilities(config, declared)
            }) {
                Ok(installed) => out.projections = installed,
                Err(_) => tracing::warn!("projection publication refresh failed; retrying"),
            }
        }
        Err(_) => tracing::warn!("projection owner unavailable for refresh"),
    }
    if out.profiles || out.projections {
        tracing::info!(
            profiles = out.profiles,
            projections = out.projections,
            "followed a publication from another replica"
        );
    }
    out
}

/// Follow publications until `stop`. Only a shared (PostgreSQL) store has
/// other replicas to follow.
#[cfg(feature = "postgres")]
pub async fn run(services: Services, mut stop: watch::Receiver<bool>) {
    let crate::store::Store::Postgres(pg) = &services.store else {
        return;
    };
    let wake = std::sync::Arc::new(tokio::sync::Notify::new());
    let listener = tokio::spawn(pg.clone().follow_publications(wake.clone(), LISTEN_RETRY));
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => break,
            _ = wake.notified() => {}
            _ = tick.tick() => {}
        }
        let services = services.clone();
        if tokio::task::spawn_blocking(move || refresh(&services))
            .await
            .is_err()
        {
            tracing::warn!("publication refresh task failed");
        }
    }
    listener.abort();
}

/// Without the PostgreSQL backend there is no other replica to follow.
#[cfg(not(feature = "postgres"))]
pub async fn run(_services: Services, _stop: watch::Receiver<bool>) {}

#[cfg(test)]
mod tests {
    #[test]
    fn the_poll_bound_is_within_two_seconds() {
        assert!(super::POLL <= std::time::Duration::from_secs(2));
    }
}
