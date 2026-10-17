//! Per-provider outbound TLS trust for an OIDC provider: a private CA
//! (`tls.ca_file`) that replaces the built-in roots, and an optional client
//! certificate (`tls.client_certificate_file` + `tls.client_key_file`) presented to
//! the provider (mutual TLS, RFC 8705 `tls_client_auth`). Discovery, JWKS,
//! token and userinfo all go through the provider's one client, so they share
//! these settings. Certificate and host-name verification always stay on.
//!
//! The files are read like the other reloadable TLS material
//! ([`crate::reload`]): polled by content digest every
//! `reload.tls_interval_secs` (default 10 s, `0` turns polling off),
//! parsed and checked completely before anything changes, then the client is
//! swapped; invalid material keeps the previous client and raises
//! `hopae_tls_reload_failing{name="provider:<id>"}`.
//!
//! Only providers from the configuration file (`managed_by: file`) may name
//! files: the admin API cannot point Hopae at a file on its host.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::reload::{Outcome, note_metrics};
use crate::telemetry::counters;

/// How often the files are re-read by default (`reload.tls_interval_secs`).
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The poll interval in seconds, `0` = off; set from
/// `reload.tls_interval_secs` at start (process-wide, like the TLS poller).
static POLL_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(POLL_INTERVAL.as_secs());

/// Follow `reload.tls_interval_secs` (`None`: polling off).
pub fn set_poll_interval(interval: Option<Duration>) {
    POLL_SECS.store(
        interval.map_or(0, |d| d.as_secs().max(1)),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The current poll interval, `None` when polling is off.
pub fn poll_interval() -> Option<Duration> {
    match POLL_SECS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(Duration::from_secs(n)),
    }
}

/// Whether a poll is due by `next` (and, if so, schedule the next one).
pub(crate) fn due(next: &Mutex<Instant>) -> bool {
    due_every(next, poll_interval())
}

/// [`due`] for a given interval (`None`: never).
pub(crate) fn due_every(next: &Mutex<Instant>, interval: Option<Duration>) -> bool {
    let Some(interval) = interval else {
        return false;
    };
    let mut next = next.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    if now < *next {
        return false;
    }
    *next = now + interval;
    true
}

/// `1` for the trust source a provider's client uses
/// (`provider`, `source` = `ca_file` or `system`).
pub const PROVIDER_TLS_TRUST: &str = "hopae_provider_tls_trust";

/// The configured files (absolute paths).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustFiles {
    pub ca: Option<PathBuf>,
    pub client: Option<(PathBuf, PathBuf)>,
}

impl TrustFiles {
    /// Read `tls.ca_file`, `tls.client_certificate_file`, `tls.client_key_file`
    /// from a provider's stored configuration. `None` when none is set.
    pub fn of_config(cfg: &Value) -> Result<Option<TrustFiles>, &'static str> {
        let tls = match cfg.get("tls") {
            None | Some(Value::Null) => return Ok(None),
            Some(t @ Value::Object(_)) => t,
            Some(_) => return Err("tls must be an object"),
        };
        if let Some(o) = tls.as_object()
            && o.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "ca_file" | "client_certificate_file" | "client_key_file"
                )
            })
        {
            return Err("unknown tls key");
        }
        let path = |k: &str| -> Result<Option<PathBuf>, &'static str> {
            match tls.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if Path::new(s).is_absolute() && s.len() <= 4096 => {
                    Ok(Some(PathBuf::from(s)))
                }
                Some(_) => Err("TLS file paths must be absolute"),
            }
        };
        let ca = path("ca_file")?;
        let client = match (path("client_certificate_file")?, path("client_key_file")?) {
            (None, None) => None,
            (Some(c), Some(k)) => Some((c, k)),
            _ => return Err("client_certificate_file and client_key_file go together"),
        };
        if ca.is_none() && client.is_none() {
            return Ok(None);
        }
        Ok(Some(TrustFiles { ca, client }))
    }

    fn paths(&self) -> Vec<PathBuf> {
        let mut v = Vec::with_capacity(3);
        v.extend(self.ca.clone());
        if let Some((c, k)) = &self.client {
            v.push(c.clone());
            v.push(k.clone());
        }
        v
    }

    pub fn source(&self) -> &'static str {
        if self.ca.is_some() {
            "ca_file"
        } else {
            "system"
        }
    }
}

/// Checked material, ready to build a client from.
pub struct Material {
    pub roots: Vec<reqwest::Certificate>,
    pub identity: Option<reqwest::Identity>,
    pub ca_fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
}

impl Material {
    /// A summary for logs: the CA's and the client certificate's fingerprints.
    fn print(&self) -> String {
        match (&self.ca_fingerprint, &self.client_fingerprint) {
            (Some(ca), Some(c)) => format!("ca {ca}, client {c}"),
            (Some(ca), None) => format!("ca {ca}"),
            (None, Some(c)) => format!("client {c}"),
            (None, None) => String::new(),
        }
    }
}

/// Parse and check the files' contents (in [`TrustFiles::paths`] order): a
/// CA file with at least one certificate, a certificate chain with its
/// matching key.
pub fn material(files: &TrustFiles, bytes: &[Vec<u8>]) -> anyhow::Result<Material> {
    let mut at = 0;
    let mut roots = Vec::new();
    let mut ca_fingerprint = None;
    if files.ca.is_some() {
        let pem = &bytes[at];
        at += 1;
        let store = crate::reload::roots(pem)?;
        anyhow::ensure!(
            store.len() <= 64,
            "the CA file holds more than 64 certificates"
        );
        let certs = crate::reload::certificates(pem)?;
        ca_fingerprint = Some(crate::reload::fingerprint(&certs[0]));
        for c in &certs {
            roots.push(reqwest::Certificate::from_der(c.as_ref())?);
        }
    }
    let mut identity = None;
    let mut client_fingerprint = None;
    if files.client.is_some() {
        let (cert, key) = (&bytes[at], &bytes[at + 1]);
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let (_, _, print) = crate::reload::identity(cert, key, &provider)?;
        client_fingerprint = Some(print);
        let mut pem = zeroize::Zeroizing::new(Vec::with_capacity(cert.len() + key.len() + 1));
        pem.extend_from_slice(key);
        pem.push(b'\n');
        pem.extend_from_slice(cert);
        identity = Some(
            reqwest::Identity::from_pem(&pem)
                .map_err(|_| anyhow::anyhow!("the client certificate or key is unusable"))?,
        );
    }
    Ok(Material {
        roots,
        identity,
        ca_fingerprint,
        client_fingerprint,
    })
}

/// Read and check the files now (for `hopae --check` and the start).
pub fn load(files: &TrustFiles) -> anyhow::Result<(Material, [u8; 32])> {
    let (bytes, digest) = crate::reload::snapshot(&files.paths())?;
    Ok((material(files, &bytes)?, digest))
}

#[derive(Default)]
struct State {
    ca_fingerprint: Option<String>,
    client_fingerprint: Option<String>,
    failing: bool,
    error: Option<String>,
    reloads: u64,
    last_reload_at: Option<i64>,
}

/// A provider's trust files, followed.
pub struct ProviderTrust {
    name: String,
    provider: String,
    files: TrustFiles,
    digest: Mutex<[u8; 32]>,
    next_poll: Mutex<Instant>,
    state: Mutex<State>,
}

impl ProviderTrust {
    pub fn new(provider: &str, files: TrustFiles, material: &Material, digest: [u8; 32]) -> Self {
        let name = format!("provider:{provider}");
        tracing::info!(name, fingerprint = %material.print(), "provider TLS material loaded");
        counters::set(crate::reload::TLS_RELOAD_FAILING, &[("name", &name)], 0);
        counters::set(
            PROVIDER_TLS_TRUST,
            &[("provider", provider), ("source", files.source())],
            1,
        );
        ProviderTrust {
            name,
            provider: provider.to_string(),
            files,
            digest: Mutex::new(digest),
            next_poll: Mutex::new(Instant::now()),
            state: Mutex::new(State {
                ca_fingerprint: material.ca_fingerprint.clone(),
                client_fingerprint: material.client_fingerprint.clone(),
                last_reload_at: Some(crate::reload::unix_now()),
                ..State::default()
            }),
        }
    }

    pub fn files(&self) -> &TrustFiles {
        &self.files
    }

    /// Whether a poll is due (and, if so, the next one is scheduled).
    pub fn due(&self) -> bool {
        due(&self.next_poll)
    }

    /// Re-read the files; when they changed and are valid, `install` the new
    /// material (it rebuilds the client) and record the reload.
    pub fn poll(&self, install: impl FnOnce(&Material) -> anyhow::Result<()>) -> Outcome {
        let outcome = self.check(install);
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        note_metrics(&self.name, &outcome, st.failing);
        match &outcome {
            Outcome::Unchanged => {
                st.failing = false;
                st.error = None;
            }
            Outcome::Reloaded(_) => {
                st.failing = false;
                st.error = None;
                st.reloads += 1;
                st.last_reload_at = Some(crate::reload::unix_now());
            }
            Outcome::Invalid(why) => {
                st.failing = true;
                st.error = Some(why.clone());
            }
        }
        outcome
    }

    fn check(&self, install: impl FnOnce(&Material) -> anyhow::Result<()>) -> Outcome {
        let (bytes, digest) = match crate::reload::snapshot(&self.files.paths()) {
            Ok(v) => v,
            Err(e) => return Outcome::Invalid(format!("unreadable: {e}")),
        };
        let mut last = self.digest.lock().unwrap_or_else(|p| p.into_inner());
        if *last == digest {
            return Outcome::Unchanged;
        }
        let material = match material(&self.files, &bytes) {
            Ok(m) => m,
            Err(e) => return Outcome::Invalid(e.to_string()),
        };
        if let Err(e) = install(&material) {
            return Outcome::Invalid(e.to_string());
        }
        *last = digest;
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.ca_fingerprint = material.ca_fingerprint.clone();
        st.client_fingerprint = material.client_fingerprint.clone();
        Outcome::Reloaded(material.print())
    }

    /// What the admin status shows.
    pub fn status(&self) -> Value {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "trust": self.files.source(),
            "ca_file": self.files.ca,
            "ca_fingerprint": st.ca_fingerprint,
            "client_certificate": self.files.client.is_some(),
            "client_certificate_fingerprint": st.client_fingerprint,
            "failing": st.failing,
            "error": st.error,
            "reloads": st.reloads,
            "last_reload_at": st.last_reload_at,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
}

/// The status of a provider using the built-in roots and no client certificate.
pub fn system_status() -> Value {
    json!({"trust": "system", "client_certificate": false})
}
