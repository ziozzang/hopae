//! Live reload of mounted material without a restart.
//!
//! **TLS.** Every listener with mutual TLS (the administrator listener, the
//! native gateway, the gRPC gateway) and the outbound mTLS clients of the
//! projection receiver read their certificate, key and CA files through a
//! [`ServerTls`] or [`ClientTls`]. A background task polls those files
//! (`reload.tls_interval_secs`, default 10 s) by **content digest** — no
//! file-system notifications: a Kubernetes secret volume replaces a symlink
//! (`..data`), which inotify watches on the files miss, and cert-manager may
//! rewrite a file in place. Changed material is parsed and checked completely
//! (certificate chain, private key matching the certificate, non-empty CA)
//! before anything changes; then the new configuration is swapped atomically.
//! New handshakes use it; established connections keep the material they
//! were made with. Invalid material keeps the previous configuration, raises
//! `hopae_tls_reload_failing{name}` and logs a warning; the next valid file
//! clears it. Each load logs the SHA-256 fingerprint of the leaf certificate.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::telemetry::counters;

/// Largest TLS file read (as the listeners always did).
pub const MAX_TLS_FILE: u64 = 1024 * 1024;

/// Reloads by result (`name`, `result` = `reloaded` or `invalid`).
pub const TLS_RELOADS_TOTAL: &str = "hopae_tls_reloads_total";
/// `1` while the newest material of `name` is invalid and the previous one is
/// still served; `0` otherwise (alert on it).
pub const TLS_RELOAD_FAILING: &str = "hopae_tls_reload_failing";

/// Read a whole file, refusing one larger than [`MAX_TLS_FILE`].
pub fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_TLS_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TLS_FILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS material exceeds bound",
        ));
    }
    Ok(bytes)
}

/// The files' contents and one digest over all of them (length-prefixed, so
/// moving bytes between files changes it).
pub(crate) fn snapshot(paths: &[PathBuf]) -> io::Result<(Vec<Vec<u8>>, [u8; 32])> {
    let mut hash = Sha256::new();
    let mut all = Vec::with_capacity(paths.len());
    for p in paths {
        let bytes = read_bounded(p)?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        all.push(bytes);
    }
    Ok((all, hash.finalize().into()))
}

pub(crate) fn certificates(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &pem[..]).collect::<io::Result<Vec<_>>>()?;
    anyhow::ensure!(!certs.is_empty(), "no certificate in the certificate file");
    Ok(certs)
}

pub(crate) fn private_key(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key in the key file"))
}

pub(crate) fn roots(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "the CA file holds no certificate");
    Ok(roots)
}

/// `sha256:<hex>` of the leaf certificate's DER.
pub fn fingerprint(leaf: &CertificateDer<'_>) -> String {
    let print = format!(
        "sha256:{}",
        data_encoding::HEXLOWER.encode(&Sha256::digest(leaf.as_ref()))
    );
    crate::telemetry::metrics::note_leaf(&print, leaf.as_ref());
    print
}

/// A certificate chain and its key, checked to belong together.
pub(crate) fn identity(
    cert: &[u8],
    key: &[u8],
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String)> {
    let certs = certificates(cert)?;
    let key = private_key(key)?;
    let signing = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| anyhow::anyhow!("unusable private key: {e}"))?;
    rustls::sign::CertifiedKey::new(certs.clone(), signing)
        .keys_match()
        .map_err(|e| anyhow::anyhow!("the private key does not match the certificate: {e}"))?;
    let print = fingerprint(&certs[0]);
    Ok((certs, key, print))
}

/// A mutual-TLS server configuration built exactly as the listeners always
/// built it (ring, safe default versions, mandatory client certificate from
/// `ca`, no early data), plus the leaf fingerprint.
pub fn server_config(
    cert: &[u8],
    key: &[u8],
    ca: &[u8],
    alpn: &[Vec<u8>],
) -> anyhow::Result<(ServerConfig, String)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (certs, key, print) = identity(cert, key, &provider)?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca)?), provider.clone())
            .build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = alpn.to_vec();
    config.max_early_data_size = 0;
    Ok((config, print))
}

/// Check outbound client material: a usable chain and matching key, and a CA
/// to verify the server with. Returns the client certificate's fingerprint.
pub fn check_client_material(ca: &[u8], cert: &[u8], key: &[u8]) -> anyhow::Result<String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    roots(ca)?;
    Ok(identity(cert, key, &provider)?.2)
}

/// What one poll found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Unchanged,
    Reloaded(String),
    Invalid(String),
}

/// The state a [`Status`] reports for one reloadable item.
#[derive(Clone, Debug, Default)]
struct Entry {
    fingerprint: String,
    failing: bool,
    error: Option<String>,
    reloads: u64,
    last_reload_unix: Option<i64>,
}

/// What `/v1/status` shows about reloadable material and configuration.
#[derive(Default)]
pub struct Status {
    entries: Mutex<BTreeMap<String, Entry>>,
    config: Mutex<Value>,
}

impl Status {
    fn record(&self, name: &str, f: impl FnOnce(&mut Entry)) {
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        f(map.entry(name.to_string()).or_default());
    }

    /// The configuration reload's state, as [`crate::config_reload`] reports it.
    pub fn set_config(&self, value: Value) {
        *self.config.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    pub fn to_json(&self) -> Value {
        let map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let tls: Vec<Value> = map
            .iter()
            .map(|(name, e)| {
                json!({
                    "name": name,
                    "fingerprint": e.fingerprint,
                    "failing": e.failing,
                    "error": e.error,
                    "reloads": e.reloads,
                    "last_reload_at": e.last_reload_unix,
                })
            })
            .collect();
        json!({
            "tls": tls,
            "config": self.config.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        })
    }
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The metric, gauge and log of a poll result (no status entry): also used by
/// material that keeps its own status, such as an OIDC provider's trust.
/// `was_failing` says whether `Unchanged` clears a previous failure.
pub(crate) fn note_metrics(name: &str, outcome: &Outcome, was_failing: bool) {
    match outcome {
        Outcome::Unchanged => {
            if was_failing {
                counters::set(TLS_RELOAD_FAILING, &[("name", name)], 0);
                tracing::info!(name, "TLS material is back to the material in use");
            }
        }
        Outcome::Reloaded(print) => {
            counters::inc(TLS_RELOADS_TOTAL, &[("name", name), ("result", "reloaded")]);
            counters::set(TLS_RELOAD_FAILING, &[("name", name)], 0);
            tracing::info!(name, fingerprint = %print, "TLS material reloaded");
        }
        Outcome::Invalid(why) => {
            counters::inc(TLS_RELOADS_TOTAL, &[("name", name), ("result", "invalid")]);
            counters::set(TLS_RELOAD_FAILING, &[("name", name)], 1);
            tracing::warn!(name, error = %why, "new TLS material is invalid; the previous material stays in use");
        }
    }
}

/// The shared bookkeeping of a poll result: metric, gauge, log, status.
fn note(status: &Status, name: &str, outcome: &Outcome) {
    let was_failing = {
        let map = status.entries.lock().unwrap_or_else(|p| p.into_inner());
        map.get(name).is_some_and(|e| e.failing)
    };
    note_metrics(name, outcome, was_failing);
    match outcome {
        Outcome::Unchanged => {
            if was_failing {
                status.record(name, |e| {
                    e.failing = false;
                    e.error = None;
                });
            }
        }
        Outcome::Reloaded(print) => status.record(name, |e| {
            e.fingerprint = print.clone();
            e.failing = false;
            e.error = None;
            e.reloads += 1;
            e.last_reload_unix = Some(unix_now());
        }),
        Outcome::Invalid(why) => status.record(name, |e| {
            e.failing = true;
            e.error = Some(why.clone());
        }),
    }
}

/// Applies outbound material `(ca, certificate, key)` to the clients.
pub type ApplyMaterial = Box<dyn Fn(&[u8], &[u8], &[u8]) -> anyhow::Result<()> + Send + Sync>;

/// A server's mutual-TLS configuration that follows its files.
pub struct ServerTls {
    name: &'static str,
    paths: Vec<PathBuf>,
    alpn: Vec<Vec<u8>>,
    current: ArcSwap<ServerConfig>,
    digest: Mutex<[u8; 32]>,
    status: Arc<Status>,
}

impl ServerTls {
    /// Load the material now (an error stops the start, as before).
    pub fn load(
        name: &'static str,
        settings: &crate::config::NativeGatewayTls,
        alpn: &[&[u8]],
        status: Arc<Status>,
    ) -> anyhow::Result<Arc<ServerTls>> {
        let paths = vec![
            settings.certificate.clone(),
            settings.key.clone(),
            settings.client_ca.clone(),
        ];
        let alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
        let (files, digest) = snapshot(&paths)?;
        let (config, print) = server_config(&files[0], &files[1], &files[2], &alpn)?;
        tracing::info!(name, fingerprint = %print, "TLS material loaded");
        status.record(name, |e| {
            e.fingerprint = print;
            e.last_reload_unix = Some(unix_now());
        });
        counters::set(TLS_RELOAD_FAILING, &[("name", name)], 0);
        Ok(Arc::new(ServerTls {
            name,
            paths,
            alpn,
            current: ArcSwap::from_pointee(config),
            digest: Mutex::new(digest),
            status,
        }))
    }

    /// The configuration new handshakes use.
    pub fn config(&self) -> Arc<ServerConfig> {
        self.current.load_full()
    }

    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.config())
    }

    /// Re-read the files; swap when they changed and are valid.
    pub fn poll(&self) -> Outcome {
        let outcome = self.check();
        note(&self.status, self.name, &outcome);
        outcome
    }

    fn check(&self) -> Outcome {
        let (files, digest) = match snapshot(&self.paths) {
            Ok(v) => v,
            // A file mid-rotation may be missing for a moment: retried next poll.
            Err(e) => return Outcome::Invalid(format!("unreadable: {e}")),
        };
        let mut last = self.digest.lock().unwrap_or_else(|p| p.into_inner());
        if *last == digest {
            return Outcome::Unchanged;
        }
        match server_config(&files[0], &files[1], &files[2], &self.alpn) {
            Ok((config, print)) => {
                self.current.store(Arc::new(config));
                *last = digest;
                Outcome::Reloaded(print)
            }
            Err(e) => Outcome::Invalid(e.to_string()),
        }
    }
}

/// Outbound mutual-TLS material (CA, certificate, key) applied to clients by
/// `apply`, which rebuilds their channels; established calls finish on the
/// channel they started on.
pub struct ClientTls {
    name: &'static str,
    paths: Vec<PathBuf>,
    digest: Mutex<[u8; 32]>,
    apply: ApplyMaterial,
    status: Arc<Status>,
}

impl ClientTls {
    /// Watch `ca`, `certificate`, `key`; the clients were built from their
    /// current contents (whose digest is taken now).
    pub fn watch(
        name: &'static str,
        ca: &Path,
        certificate: &Path,
        key: &Path,
        status: Arc<Status>,
        apply: ApplyMaterial,
    ) -> anyhow::Result<Arc<ClientTls>> {
        let paths = vec![
            ca.to_path_buf(),
            certificate.to_path_buf(),
            key.to_path_buf(),
        ];
        let (files, digest) = snapshot(&paths)?;
        let print = check_client_material(&files[0], &files[1], &files[2])?;
        tracing::info!(name, fingerprint = %print, "TLS client material loaded");
        status.record(name, |e| {
            e.fingerprint = print;
            e.last_reload_unix = Some(unix_now());
        });
        counters::set(TLS_RELOAD_FAILING, &[("name", name)], 0);
        Ok(Arc::new(ClientTls {
            name,
            paths,
            digest: Mutex::new(digest),
            apply,
            status,
        }))
    }

    pub fn poll(&self) -> Outcome {
        let outcome = self.check();
        note(&self.status, self.name, &outcome);
        outcome
    }

    fn check(&self) -> Outcome {
        let (files, digest) = match snapshot(&self.paths) {
            Ok(v) => v,
            Err(e) => return Outcome::Invalid(format!("unreadable: {e}")),
        };
        let mut last = self.digest.lock().unwrap_or_else(|p| p.into_inner());
        if *last == digest {
            return Outcome::Unchanged;
        }
        let print = match check_client_material(&files[0], &files[1], &files[2]) {
            Ok(p) => p,
            Err(e) => return Outcome::Invalid(e.to_string()),
        };
        match (self.apply)(&files[0], &files[1], &files[2]) {
            Ok(()) => {
                *last = digest;
                Outcome::Reloaded(print)
            }
            Err(e) => Outcome::Invalid(e.to_string()),
        }
    }
}

/// Everything the TLS poller watches.
#[derive(Default, Clone)]
pub struct TlsWatch {
    pub servers: Vec<Arc<ServerTls>>,
    pub clients: Vec<Arc<ClientTls>>,
}

impl TlsWatch {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.clients.is_empty()
    }

    pub fn poll(&self) {
        for s in &self.servers {
            s.poll();
        }
        for c in &self.clients {
            c.poll();
        }
    }

    /// Poll every `interval` until `stop` turns true. File reads run on the
    /// blocking pool.
    pub async fn run(
        self,
        interval: std::time::Duration,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let watch = self.clone();
                    let _ = tokio::task::spawn_blocking(move || watch.poll()).await;
                }
                _ = async { let _ = stop.wait_for(|s| *s).await; } => return,
            }
        }
    }
}

#[cfg(test)]
#[path = "reload_tests.rs"]
pub(crate) mod tests;
