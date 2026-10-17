//! OpenMetrics exposition (`GET /metrics` on the admin listener) and the
//! allocation-free recorders for hot paths.
//!
//! Hot-path series live in fixed-capacity [`Family`] tables: a recorder hashes
//! its label values, probes the table and increments an atomic. A series'
//! label strings are stored once, the first time it is seen; after that a
//! recording takes no lock and allocates nothing. Every label value comes from
//! a bounded set (static reason codes, configured provider ids, fixed factor
//! and surface names): never a subject, a user id, an email or an address. A
//! table that is full counts into `hopae_metrics_series_overflow_total`
//! instead of growing.
//!
//! The older [`super::counters`] table (string-keyed, behind one lock) is
//! exposed as well; its series keep their names.
use std::fmt::Write as _;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{LazyLock, OnceLock};
use std::time::Instant;

/// `Content-Type` of [`render`].
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

struct Slot<const L: usize> {
    values: [Box<str>; L],
    count: AtomicU64,
}

/// A counter family with `L` labels and room for `cap` series.
pub struct Family<const L: usize> {
    name: &'static str,
    help: &'static str,
    labels: [&'static str; L],
    slots: Box<[OnceLock<Slot<L>>]>,
    hasher: std::hash::RandomState,
}

/// Series that did not fit their family (a bug or a hostile configuration).
static OVERFLOW: AtomicU64 = AtomicU64::new(0);

impl<const L: usize> Family<L> {
    pub fn new(
        name: &'static str,
        help: &'static str,
        labels: [&'static str; L],
        cap: usize,
    ) -> Self {
        Self {
            name,
            help,
            labels,
            slots: (0..cap).map(|_| OnceLock::new()).collect(),
            hasher: std::hash::RandomState::new(),
        }
    }

    /// Add `n` to the series `values`. Allocation-free once the series exists.
    pub fn add(&self, values: [&str; L], n: u64) {
        let mut h = self.hasher.build_hasher();
        for v in values {
            h.write(v.as_bytes());
            h.write_u8(0xff);
        }
        let len = self.slots.len();
        let start = (h.finish() as usize) % len;
        for i in 0..len {
            let slot = &self.slots[(start + i) % len];
            let found = match slot.get() {
                Some(s) => s,
                None => slot.get_or_init(|| Slot {
                    values: values.map(Box::from),
                    count: AtomicU64::new(0),
                }),
            };
            if found.values.iter().zip(values).all(|(a, b)| **a == *b) {
                found.count.fetch_add(n, Relaxed);
                return;
            }
        }
        OVERFLOW.fetch_add(n, Relaxed);
    }

    pub fn inc(&self, values: [&str; L]) {
        self.add(values, 1);
    }

    /// The value of one series (0 if never recorded).
    pub fn get(&self, values: [&str; L]) -> u64 {
        self.slots
            .iter()
            .filter_map(OnceLock::get)
            .find(|s| s.values.iter().zip(values).all(|(a, b)| **a == *b))
            .map_or(0, |s| s.count.load(Relaxed))
    }

    fn render(&self, out: &mut String) {
        let family = self.name.strip_suffix("_total").unwrap_or(self.name);
        let _ = writeln!(
            out,
            "# TYPE {family} counter\n# HELP {family} {}",
            self.help
        );
        let mut rows: Vec<(String, u64)> = self
            .slots
            .iter()
            .filter_map(OnceLock::get)
            .map(|s| {
                let labels = self
                    .labels
                    .iter()
                    .zip(s.values.iter())
                    .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
                    .collect::<Vec<_>>()
                    .join(",");
                (labels, s.count.load(Relaxed))
            })
            .collect();
        rows.sort();
        for (labels, v) in rows {
            let _ = writeln!(out, "{family}_total{{{labels}}} {v}");
        }
    }
}

fn escape(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' | '\\' => {
                s.push('\\');
                s.push(c);
            }
            '\n' => s.push_str("\\n"),
            c => s.push(c),
        }
    }
    s
}

/// Where an authentication decision was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// HTTP forward-auth (`GET /_hopae/verify` from a gateway).
    ForwardAuth = 0,
    /// HOP1 native framed verify.
    Hop1 = 1,
    /// gRPC (`Authentication.Verify` and the receipt/projection services).
    Grpc = 2,
}
impl Surface {
    pub fn name(self) -> &'static str {
        ["forward_auth", "hop1", "grpc"][self as usize]
    }
}

/// Seconds; the upper bounds of the latency buckets.
const BUCKETS_US: [u64; 12] = [
    250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000, 5_000_000,
];
const BUCKET_LABELS: [&str; 12] = [
    "0.00025", "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "1.0",
    "5.0",
];
struct Histogram {
    buckets: [AtomicU64; 12],
    count: AtomicU64,
    sum_us: AtomicU64,
}
impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; 12],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }
}
static LATENCY: [Histogram; 3] = [const { Histogram::new() }; 3];

/// Record one verify's latency on `surface`. Allocation-free.
pub fn observe(surface: Surface, started: Instant) {
    let us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let h = &LATENCY[surface as usize];
    if let Some(i) = BUCKETS_US.iter().position(|b| us <= *b) {
        h.buckets[i].fetch_add(1, Relaxed);
    }
    h.count.fetch_add(1, Relaxed);
    h.sum_us.fetch_add(us, Relaxed);
}

/// Decisions timed on `surface` so far (tests, introspection).
pub fn latency_count(surface: Surface) -> u64 {
    LATENCY[surface as usize].count.load(Relaxed)
}

/// Authentication decisions by surface, provider (on allow; `none`
/// otherwise), outcome and reason code.
pub static AUTH_OUTCOMES: LazyLock<Family<4>> = LazyLock::new(|| {
    Family::new(
        "hopae_auth_outcomes_total",
        "Authentication decisions by surface, provider, outcome and reason.",
        ["surface", "provider", "outcome", "reason"],
        2048,
    )
});
/// gRPC calls by profile (the service family) and status code.
pub static GRPC_REQUESTS: LazyLock<Family<2>> = LazyLock::new(|| {
    Family::new(
        "hopae_grpc_requests_total",
        "gRPC calls by authentication profile and status code.",
        ["profile", "code"],
        256,
    )
});
/// Portal logins by provider, outcome and reason.
pub static LOGINS: LazyLock<Family<3>> = LazyLock::new(|| {
    Family::new(
        "hopae_logins_total",
        "Portal logins by provider, outcome and reason.",
        ["provider", "outcome", "reason"],
        1024,
    )
});
/// Sessions created, by provider.
pub static SESSIONS_CREATED: LazyLock<Family<1>> = LazyLock::new(|| {
    Family::new(
        "hopae_sessions_created_total",
        "Sessions created, by provider.",
        ["provider"],
        256,
    )
});
/// Sessions ended (terminated, logged out, revoked), by reason.
pub static SESSIONS_REVOKED: LazyLock<Family<1>> = LazyLock::new(|| {
    Family::new(
        "hopae_sessions_revoked_total",
        "Sessions ended before expiry (logout, termination, revocation), by reason.",
        ["reason"],
        256,
    )
});
/// Application handles revoked, by reason.
pub static HANDLES_REVOKED: LazyLock<Family<1>> = LazyLock::new(|| {
    Family::new(
        "hopae_handles_revoked_total",
        "Application session handles revoked, by reason.",
        ["reason"],
        256,
    )
});
/// Second-factor checks (step-up and login MFA), by factor and outcome.
pub static STEPUP: LazyLock<Family<2>> = LazyLock::new(|| {
    Family::new(
        "hopae_stepup_results_total",
        "Second-factor checks (step-up and login MFA), by factor and outcome.",
        ["factor", "outcome"],
        64,
    )
});
/// Passkey (WebAuthn) ceremonies, by ceremony and outcome.
pub static PASSKEY: LazyLock<Family<2>> = LazyLock::new(|| {
    Family::new(
        "hopae_passkey_ceremonies_total",
        "Passkey (WebAuthn) ceremonies, by ceremony and outcome.",
        ["ceremony", "outcome"],
        64,
    )
});
/// Requests refused by a rate limit, by surface.
pub static RATE_LIMITED: LazyLock<Family<1>> = LazyLock::new(|| {
    Family::new(
        "hopae_rate_limited_total",
        "Requests refused by a rate limit, by surface.",
        ["surface"],
        16,
    )
});
/// Store failures by kind (`busy`, `queue_full`, `conflict`, `other`).
pub static STORE_FAILURES: LazyLock<Family<1>> = LazyLock::new(|| {
    Family::new(
        "hopae_store_failures_total",
        "Store failures by kind (busy = SQLite locked past the busy timeout, or a PostgreSQL serialization failure or deadlock).",
        ["kind"],
        16,
    )
});

/// Map a recorded event onto the lifecycle families (sessions, logins,
/// factors, passkeys). Called once per event row written.
pub fn event(ev: &crate::event::types::Event) {
    use crate::event::types::{EventKind as K, Outcome};
    let outcome = ev.outcome.as_str();
    let reason = ev.reason.map_or("none", |r| r.0);
    let provider = ev.provider_id.as_ref().map_or("none", |p| p.as_str());
    match ev.kind {
        K::LoginSucceeded | K::LoginFailed => LOGINS.inc([provider, outcome, reason]),
        K::SessionCreated => SESSIONS_CREATED.inc([provider]),
        K::SessionTerminated => SESSIONS_REVOKED.inc([reason]),
        K::HandleRevoked => HANDLES_REVOKED.inc([reason]),
        K::FactorTotpConsumed => STEPUP.inc(["totp", outcome]),
        K::FactorExternalConsumed => STEPUP.inc(["external", outcome]),
        K::FactorRecoveryCodeUsed => STEPUP.inc(["recovery_code", outcome]),
        K::FactorWebauthnUsed => {
            STEPUP.inc(["webauthn", outcome]);
            PASSKEY.inc(["authenticate", outcome]);
        }
        K::FactorWebauthnFailed => {
            STEPUP.inc(["webauthn", "failure"]);
            PASSKEY.inc(["authenticate", "failure"]);
        }
        K::FactorWebauthnCloneSuspected => PASSKEY.inc(["authenticate", "clone_suspected"]),
        K::FactorWebauthnRegistered => PASSKEY.inc([
            "register",
            if ev.outcome == Outcome::Failure {
                "failure"
            } else {
                "success"
            },
        ]),
        K::FactorWebauthnRevoked => PASSKEY.inc(["revoke", outcome]),
        _ => {}
    }
}

/// gRPC profile of a request path (`/package.Service/Method`).
pub fn grpc_profile(path: &str) -> &'static str {
    let service = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .and_then(|s| s.rsplit('.').next())
        .unwrap_or("");
    match service {
        "Authentication" => "verify",
        "AuthenticationReceipts" => "service_receipt",
        "WorkloadAuthenticationReceipts" => "workload_receipt",
        "HumanAuthenticationReceipts" => "human_receipt",
        "ProjectionPlans" => "projection_plan",
        "CredentialProjection" | "ObservedCredentialProjection" => "service_projection",
        "WorkloadObservedCredentialProjection" => "workload_projection",
        "HumanObservedCredentialProjection" => "human_projection",
        _ => "other",
    }
}

/// gRPC status code name of a `grpc-status` header value (`ok` if absent).
pub fn grpc_code(status: Option<&[u8]>) -> &'static str {
    const NAMES: [&str; 17] = [
        "ok",
        "cancelled",
        "unknown",
        "invalid_argument",
        "deadline_exceeded",
        "not_found",
        "already_exists",
        "permission_denied",
        "resource_exhausted",
        "failed_precondition",
        "aborted",
        "out_of_range",
        "unimplemented",
        "internal",
        "unavailable",
        "data_loss",
        "unauthenticated",
    ];
    match status {
        None => "ok",
        Some(v) => std::str::from_utf8(v)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .and_then(|i| NAMES.get(i).copied())
            .unwrap_or("unknown"),
    }
}

pin_project_lite::pin_project! {
    /// Future of [`Timed`]: records latency and the gRPC outcome on completion.
    pub struct TimedFuture<F> {
        #[pin]
        inner: F,
        started: Instant,
        profile: &'static str,
    }
}
impl<F, B, E> std::future::Future for TimedFuture<F>
where
    F: std::future::Future<Output = Result<axum::http::Response<B>, E>>,
{
    type Output = F::Output;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        let this = self.project();
        let out = std::task::ready!(this.inner.poll(cx));
        let code = match &out {
            Ok(r) => grpc_code(r.headers().get("grpc-status").map(|v| v.as_bytes())),
            Err(_) => "transport_error",
        };
        GRPC_REQUESTS.inc([this.profile, code]);
        observe(Surface::Grpc, *this.started);
        std::task::Poll::Ready(out)
    }
}
/// gRPC server layer: per-call latency and outcome by profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrpcMetricsLayer;
impl<S> tower::Layer<S> for GrpcMetricsLayer {
    type Service = Timed<S>;
    fn layer(&self, inner: S) -> Timed<S> {
        Timed(inner)
    }
}
#[derive(Clone, Debug)]
pub struct Timed<S>(S);
impl<S, B, RB> tower::Service<axum::http::Request<B>> for Timed<S>
where
    S: tower::Service<axum::http::Request<B>, Response = axum::http::Response<RB>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TimedFuture<S::Future>;
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), S::Error>> {
        self.0.poll_ready(cx)
    }
    fn call(&mut self, request: axum::http::Request<B>) -> Self::Future {
        let profile = grpc_profile(request.uri().path());
        TimedFuture {
            started: Instant::now(),
            profile,
            inner: self.0.call(request),
        }
    }
}

/// Leaf `notAfter` (Unix seconds) by certificate fingerprint, filled when TLS
/// material is loaded ([`crate::reload::fingerprint`]).
static LEAF_EXPIRY: LazyLock<std::sync::Mutex<std::collections::HashMap<String, i64>>> =
    LazyLock::new(Default::default);

/// Remember the expiry of a loaded leaf certificate.
pub fn note_leaf(fingerprint: &str, der: &[u8]) {
    let Some(not_after) = openssl::x509::X509::from_der(der).ok().and_then(|c| {
        let epoch = openssl::asn1::Asn1Time::from_unix(0).ok()?;
        let d = epoch.diff(c.not_after()).ok()?;
        Some(i64::from(d.days) * 86_400 + i64::from(d.secs))
    }) else {
        return;
    };
    let mut map = LEAF_EXPIRY.lock().unwrap_or_else(|p| p.into_inner());
    if map.len() >= 256 {
        map.clear();
    }
    map.insert(fingerprint.to_owned(), not_after);
}
/// `notAfter` of a loaded leaf, by fingerprint.
pub fn leaf_not_after(fingerprint: &str) -> Option<i64> {
    LEAF_EXPIRY
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(fingerprint)
        .copied()
}

/// Write a gauge family (`samples` are preformatted label sets and values).
pub fn gauge(out: &mut String, name: &str, help: &str, samples: &[(String, i64)]) {
    let _ = writeln!(out, "# TYPE {name} gauge\n# HELP {name} {help}");
    for (labels, v) in samples {
        if labels.is_empty() {
            let _ = writeln!(out, "{name} {v}");
        } else {
            let _ = writeln!(out, "{name}{{{labels}}} {v}");
        }
    }
}
/// `k="v"` with the value escaped.
pub fn label(k: &str, v: &str) -> String {
    format!("{k}=\"{}\"", escape(v))
}

/// The process-wide part of the exposition: the hot-path families, the
/// latency histograms and the [`super::counters`] table. The caller adds the
/// store-derived gauges and then [`finish`]es.
pub fn render(out: &mut String) {
    AUTH_OUTCOMES.render(out);
    GRPC_REQUESTS.render(out);
    LOGINS.render(out);
    STEPUP.render(out);
    PASSKEY.render(out);
    for f in [
        &*SESSIONS_CREATED,
        &*SESSIONS_REVOKED,
        &*HANDLES_REVOKED,
        &*RATE_LIMITED,
        &*STORE_FAILURES,
    ] {
        f.render(out);
    }
    let _ = writeln!(
        out,
        "# TYPE hopae_verify_duration_seconds histogram\n# HELP hopae_verify_duration_seconds Authentication decision latency by surface."
    );
    for (i, h) in LATENCY.iter().enumerate() {
        let surface = [Surface::ForwardAuth, Surface::Hop1, Surface::Grpc][i].name();
        let mut cumulative = 0;
        for (b, le) in BUCKET_LABELS.iter().enumerate() {
            cumulative += h.buckets[b].load(Relaxed);
            let _ = writeln!(
                out,
                "hopae_verify_duration_seconds_bucket{{surface=\"{surface}\",le=\"{le}\"}} {cumulative}"
            );
        }
        let count = h.count.load(Relaxed);
        let _ = writeln!(
            out,
            "hopae_verify_duration_seconds_bucket{{surface=\"{surface}\",le=\"+Inf\"}} {count}\nhopae_verify_duration_seconds_count{{surface=\"{surface}\"}} {count}\nhopae_verify_duration_seconds_sum{{surface=\"{surface}\"}} {}",
            h.sum_us.load(Relaxed) as f64 / 1e6
        );
    }
    let _ = writeln!(
        out,
        "# TYPE hopae_metrics_series_overflow counter\n# HELP hopae_metrics_series_overflow Recordings dropped because a metric family was full.\nhopae_metrics_series_overflow_total {}",
        OVERFLOW.load(Relaxed)
    );
    counters_table(out);
}

/// The legacy counters table, grouped by name: `*_total` as counters, the
/// rest as gauges.
fn counters_table(out: &mut String) {
    let snapshot = super::counters::snapshot();
    let Some(map) = snapshot.as_object() else {
        return;
    };
    let mut families: std::collections::BTreeMap<&str, Vec<(&str, i64)>> = Default::default();
    for (key, value) in map {
        let (name, labels) = match key.find('{') {
            Some(i) => (&key[..i], &key[i + 1..key.len() - 1]),
            None => (key.as_str(), ""),
        };
        // Test-only series and anything not namespaced stay out.
        if !name.starts_with("hopae_") {
            continue;
        }
        families
            .entry(name)
            .or_default()
            .push((labels, value.as_i64().unwrap_or(0)));
    }
    for (name, samples) in families {
        let (family, kind) = match name.strip_suffix("_total") {
            Some(f) => (f, "counter"),
            None => (name, "gauge"),
        };
        let _ = writeln!(out, "# TYPE {family} {kind}");
        for (labels, v) in samples {
            let v = if kind == "counter" { v.max(0) } else { v };
            if labels.is_empty() {
                let _ = writeln!(out, "{name} {v}");
            } else {
                let _ = writeln!(out, "{name}{{{labels}}} {v}");
            }
        }
    }
}

/// End the exposition.
pub fn finish(out: &mut String) {
    out.push_str("# EOF\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_count_per_label_set_and_overflow_when_full() {
        let f = Family::<2>::new("hopae_test_family_total", "test", ["a", "b"], 2);
        f.inc(["x", "y"]);
        f.add(["x", "y"], 2);
        f.inc(["x", "z"]);
        let before = OVERFLOW.load(Relaxed);
        f.inc(["q", "r"]);
        assert_eq!(f.get(["x", "y"]), 3);
        assert_eq!(f.get(["x", "z"]), 1);
        assert_eq!(f.get(["q", "r"]), 0);
        assert!(OVERFLOW.load(Relaxed) > before);
        let mut out = String::new();
        f.render(&mut out);
        assert!(out.contains("# TYPE hopae_test_family counter"));
        assert!(out.contains("hopae_test_family_total{a=\"x\",b=\"y\"} 3"));
    }

    #[test]
    fn events_map_to_lifecycle_families_without_subjects() {
        use crate::crypto::{SeededRng, SystemClock};
        use crate::event::types::{EventBuilder, EventKind as K, Outcome, Reason};
        let provider = crate::provider::types::ProviderId::new("metrics-test-idp");
        let ev = |kind, outcome| {
            EventBuilder::new(&SystemClock, &SeededRng::new(9), kind, outcome, "r_m")
                .provider(&provider)
                .reason(Reason("metrics_test_reason"))
                .build()
        };
        let created = SESSIONS_CREATED.get(["metrics-test-idp"]);
        let failed = LOGINS.get(["metrics-test-idp", "failure", "metrics_test_reason"]);
        let revoked = SESSIONS_REVOKED.get(["metrics_test_reason"]);
        let totp = STEPUP.get(["totp", "success"]);
        let passkey = PASSKEY.get(["authenticate", "failure"]);
        let register = PASSKEY.get(["register", "success"]);
        event(&ev(K::SessionCreated, Outcome::Success));
        event(&ev(K::LoginFailed, Outcome::Failure));
        event(&ev(K::SessionTerminated, Outcome::Info));
        event(&ev(K::FactorTotpConsumed, Outcome::Success));
        event(&ev(K::FactorWebauthnFailed, Outcome::Failure));
        event(&ev(K::FactorWebauthnRegistered, Outcome::Success));
        event(&ev(K::AdminRead, Outcome::Success)); // not a lifecycle family
        assert_eq!(SESSIONS_CREATED.get(["metrics-test-idp"]), created + 1);
        assert_eq!(
            LOGINS.get(["metrics-test-idp", "failure", "metrics_test_reason"]),
            failed + 1
        );
        assert_eq!(SESSIONS_REVOKED.get(["metrics_test_reason"]), revoked + 1);
        assert_eq!(STEPUP.get(["totp", "success"]), totp + 1);
        assert_eq!(PASSKEY.get(["authenticate", "failure"]), passkey + 1);
        assert_eq!(PASSKEY.get(["register", "success"]), register + 1);
    }

    #[test]
    fn grpc_profiles_and_codes_are_bounded() {
        assert_eq!(
            grpc_profile("/hangang.hopae.v1.WorkloadAuthenticationReceipts/IssueWorkload"),
            "workload_receipt"
        );
        assert_eq!(grpc_profile("/x.Unknown/M"), "other");
        assert_eq!(grpc_code(None), "ok");
        assert_eq!(grpc_code(Some(b"7")), "permission_denied");
        assert_eq!(grpc_code(Some(b"99")), "unknown");
    }

    #[test]
    fn exposition_is_openmetrics_shaped() {
        AUTH_OUTCOMES.inc(["forward_auth", "none", "deny", "unknown_handle"]);
        observe(Surface::Hop1, Instant::now());
        super::super::counters::inc("hopae_test_exposition_total", &[("k", "v")]);
        let mut out = String::new();
        render(&mut out);
        finish(&mut out);
        assert!(out.ends_with("# EOF\n"));
        assert!(out.contains("# TYPE hopae_auth_outcomes counter"));
        assert!(out.contains("hopae_verify_duration_seconds_count{surface=\"hop1\"}"));
        assert!(out.contains("# TYPE hopae_test_exposition counter"));
        assert!(out.contains("hopae_test_exposition_total{k=\"v\"} 1"));
        // Every family's TYPE line is unique (no family split or duplicated).
        let types: Vec<&str> = out.lines().filter(|l| l.starts_with("# TYPE ")).collect();
        let mut unique = types.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(types.len(), unique.len());
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit_once(' ').unwrap().1;
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }
}
