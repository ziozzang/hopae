//! Route-scoped, read-only service credentials for machine callers of the
//! admin listener (first consumer: Pumgye policy v2 reading the membership
//! projection and the subject lifecycle feed; Hangang ADR 0021).
//!
//! A request authenticates with **both**
//!
//! * the admin listener's mutual TLS (`listen.admin_tls`), whose verified
//!   client certificate must match the credential's binding (SHA-256 of the
//!   SubjectPublicKeyInfo and/or an exact subject alternative name), and
//! * `Authorization: Bearer hsc1.<credential id>.<secret>`, a 256-bit random
//!   secret whose domain-separated SHA-256 is stored (current and, during a
//!   rotation, next),
//!
//! plus `x-hopae-audience` naming this instance's service audience, which the
//! credential must allow. It is then admitted only to its exact
//! `METHOD /path` allowlist, which can only ever name read routes of
//! [`READABLE`]; a mutation route is refused whatever the stored
//! configuration says. A per-credential token bucket bounds the rate. Every
//! answered read writes its usual `admin.read` record with
//! `attrs.credential_id`; refusals are counted and logged without the secret.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use sha2::{Digest as _, Sha256};

use super::{AdminState, Principal, api};
use crate::crypto::{Secret, ct_eq};
use crate::telemetry::counters;

/// Token prefix (version 1).
pub const TOKEN_PREFIX: &str = "hsc1.";
/// Header carrying the audience the caller intends the bearer for.
pub const AUDIENCE_HEADER: &str = "x-hopae-audience";
const DIGEST_DOMAIN: &[u8] = b"hopae:service-credential:v1\0";
/// Most routes, audiences per credential.
pub const MAX_ROUTES: usize = 32;
pub const MAX_AUDIENCES: usize = 8;
/// Longest lifetime a credential may be created with.
pub const MAX_LIFETIME_SECS: i64 = 400 * 86_400;

/// Every route a service credential may ever be granted: reads of the admin
/// listener that change nothing but their audit record. Mutations
/// ([`super::auth::is_mutation`]) are never in this list and are refused
/// again at request time.
pub const READABLE: &[(&str, &str)] = &[
    ("POST", "/v1/groups/projection/snapshot"),
    ("POST", "/v1/groups/projection/changes"),
    ("POST", "/v1/subjects/lifecycle"),
    ("POST", "/v1/subjects/lifecycle/snapshot"),
    ("POST", "/v1/subjects/resolve"),
    ("POST", "/v1/subjects/search"),
    ("POST", "/v1/subjects/groups"),
    ("POST", "/v1/groups/search"),
    ("POST", "/v1/groups/get"),
    ("POST", "/v1/explain/authentication"),
    ("GET", "/v1/status"),
    ("GET", "/metrics"),
];

/// The routes Pumgye policy v2 needs (`--route` default of the CLI preset).
pub const PUMGYE_V2_ROUTES: &[&str] = &[
    "POST /v1/groups/projection/snapshot",
    "POST /v1/groups/projection/changes",
    "POST /v1/subjects/lifecycle",
    "POST /v1/subjects/lifecycle/snapshot",
];

/// The route a Prometheus scraper needs (`--preset metrics`).
pub const METRICS_ROUTES: &[&str] = &["GET /metrics"];

/// The verified client certificate of an admin mTLS connection, inserted by
/// the admin listener's TLS server (never from a header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCertificate {
    /// Lowercase hex SHA-256 of the leaf's DER SubjectPublicKeyInfo.
    pub spki_sha256: String,
    /// The leaf's DNS and URI subject alternative names.
    pub sans: Vec<String>,
}

impl PeerCertificate {
    /// Facts of a DER leaf certificate (already verified by the TLS stack).
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let cert = openssl::x509::X509::from_der(der).ok()?;
        let spki = cert.public_key().ok()?.public_key_to_der().ok()?;
        let mut sans = Vec::new();
        if let Some(names) = cert.subject_alt_names() {
            for n in names.iter() {
                if let Some(v) = n.dnsname().or_else(|| n.uri()) {
                    sans.push(v.to_owned());
                }
            }
        }
        Some(Self {
            spki_sha256: data_encoding::HEXLOWER.encode(&Sha256::digest(&spki)),
            sans,
        })
    }
}

/// The authenticated service caller of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCaller {
    pub credential_id: String,
    /// `current` or `next` (during a rotation).
    pub slot: &'static str,
}

/// A credential id: 3–48 lowercase letters, digits and inner `-`.
pub fn valid_id(id: &str) -> bool {
    (3..=48).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// `(id, secret)` of a presented token.
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    (valid_id(id)
        && secret.len() == 43
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some((id, secret))
}

/// The stored digest of a secret (lowercase hex).
pub fn digest(id: &str, secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(id.as_bytes());
    h.update([0]);
    h.update(secret.as_bytes());
    data_encoding::HEXLOWER.encode(&h.finalize())
}

/// A new token for `id` and the digest to store.
pub fn mint(rng: &dyn crate::crypto::Rng, id: &str) -> (Secret, String) {
    let secret = crate::crypto::random_token(rng, 32);
    let digest = digest(id, secret.expose());
    (
        Secret::new(format!("{TOKEN_PREFIX}{id}.{}", secret.expose())),
        digest,
    )
}

/// Whether `METHOD /path` may ever be granted to a service credential.
pub fn grantable(route: &str) -> bool {
    let Some((method, path)) = route.split_once(' ') else {
        return false;
    };
    READABLE.iter().any(|(m, p)| *m == method && *p == path)
        && !method
            .parse::<Method>()
            .is_ok_and(|m| super::auth::is_mutation(&m, path))
}

/// A SAN binding value: a DNS name or a `spiffe://`/`https://` URI, no
/// whitespace or control characters.
pub fn valid_san(s: &str) -> bool {
    !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Why a service request is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not over the admin mTLS listener with a verified client certificate.
    Transport,
    /// Unknown id, wrong secret, revoked or expired: one answer.
    Credential,
    /// The certificate does not match the credential's binding.
    Binding,
    /// Missing, duplicated or unaccepted `x-hopae-audience`.
    Audience,
    /// The route is not in the credential's allowlist, or is not readable.
    Route,
    RateLimited(u64),
    /// The store could not be read.
    Unavailable,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Transport => "service_transport_required",
            Refusal::Credential => "service_credential_rejected",
            Refusal::Binding => "service_binding_mismatch",
            Refusal::Audience => "service_audience_mismatch",
            Refusal::Route => "service_route_forbidden",
            Refusal::RateLimited(_) => "rate_limited",
            Refusal::Unavailable => "store_unavailable",
        }
    }
    pub fn respond(self) -> Response {
        let status = match self {
            Refusal::Credential => StatusCode::UNAUTHORIZED,
            Refusal::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Refusal::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::FORBIDDEN,
        };
        let mut r = api::json_error(status, self.code());
        if let Refusal::RateLimited(s) = self
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        if self == Refusal::Credential {
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        r.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

/// The bearer of a request when it is a service credential token.
pub fn presented(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let v = values.next()?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && token.starts_with(TOKEN_PREFIX)).then_some(token)
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

fn buckets() -> &'static Mutex<HashMap<(usize, String), Bucket>> {
    static B: OnceLock<Mutex<HashMap<(usize, String), Bucket>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(HashMap::new()))
}

fn take(listener: usize, id: &str, per_minute: u32, burst: u32) -> Result<(), u64> {
    let rate = f64::from(per_minute) / 60.0;
    let burst = f64::from(burst);
    let now = Instant::now();
    let mut map = buckets().lock().unwrap_or_else(|p| p.into_inner());
    if map.len() > 4096 {
        map.retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(600));
    }
    let b = map.entry((listener, id.to_owned())).or_insert(Bucket {
        tokens: burst,
        at: now,
    });
    b.tokens = (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate).min(burst);
    b.at = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        Ok(())
    } else {
        Err(((1.0 - b.tokens) / rate).ceil().max(1.0) as u64)
    }
}

fn count(result: &str) {
    counters::inc(
        counters::ADMIN_SERVICE_CREDENTIALS_TOTAL,
        &[("result", result)],
    );
}

/// Authenticate a service request. `peer` is the verified client certificate
/// of the connection (absent off the admin mTLS listener).
pub async fn authenticate(
    st: &AdminState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    peer: Option<&PeerCertificate>,
    rid: &str,
) -> Result<(Principal, ServiceCaller), Refusal> {
    let result = check(st, method, path, headers, peer).await;
    match &result {
        Ok((_, caller)) => count(if caller.slot == "next" {
            "accepted_next"
        } else {
            "accepted"
        }),
        Err(refusal) => {
            count(refusal.code());
            tracing::warn!(request_id = rid, reason = refusal.code(), %path, "service credential refused");
        }
    }
    result
}

async fn check(
    st: &AdminState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    peer: Option<&PeerCertificate>,
) -> Result<(Principal, ServiceCaller), Refusal> {
    let peer = peer.ok_or(Refusal::Transport)?;
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Refusal::Credential);
    }
    let (id, secret) = presented(headers)
        .and_then(parse_token)
        .ok_or(Refusal::Credential)?;
    let row = st
        .profile_store
        .service_credential_get(id.to_owned(), api::deadline(st))
        .await
        .map_err(|_| Refusal::Unavailable)?;
    // Compute the digest whether or not the row exists (no timing oracle on ids).
    let presented = digest(id, secret);
    let row = row.ok_or(Refusal::Credential)?;
    let now = st.clock.now().secs();
    let slot = if ct_eq(presented.as_bytes(), row.current_sha256.as_bytes()) {
        "current"
    } else if row
        .next_sha256
        .as_deref()
        .is_some_and(|n| ct_eq(presented.as_bytes(), n.as_bytes()))
    {
        "next"
    } else {
        return Err(Refusal::Credential);
    };
    if row.revoked_at.is_some() || row.expires_at <= now {
        return Err(Refusal::Credential);
    }
    if row
        .client_spki_sha256
        .as_deref()
        .is_some_and(|pin| !ct_eq(pin.as_bytes(), peer.spki_sha256.as_bytes()))
        || row
            .client_san
            .as_deref()
            .is_some_and(|san| !peer.sans.iter().any(|s| s == san))
        || (row.client_spki_sha256.is_none() && row.client_san.is_none())
    {
        return Err(Refusal::Binding);
    }
    let mut audiences = headers.get_all(AUDIENCE_HEADER).iter();
    let mut audience = audiences.next().and_then(|v| v.to_str().ok());
    // A scraper cannot always add request headers (a Prometheus Operator
    // ServiceMonitor has no header field): `GET /metrics` alone may omit the
    // audience, which then defaults to this instance's. The credential must
    // still allow that audience, and its mTLS binding and secret still apply.
    if audience.is_none() && *method == Method::GET && path == "/metrics" {
        audience = Some(st.cfg.service_audience.as_str());
    }
    if audiences.next().is_some()
        || audience
            .is_none_or(|a| a != st.cfg.service_audience || !row.audiences.iter().any(|x| x == a))
    {
        return Err(Refusal::Audience);
    }
    let route = format!("{} {}", method.as_str(), path);
    if !grantable(&route) || !row.routes.iter().any(|r| r == &route) {
        return Err(Refusal::Route);
    }
    take(
        std::ptr::from_ref(st) as usize,
        &row.credential_id,
        row.rate_per_minute,
        row.burst,
    )
    .map_err(|retry| {
        crate::telemetry::metrics::RATE_LIMITED.inc(["service_credential"]);
        Refusal::RateLimited(retry)
    })?;
    let principal = Principal {
        authority: None,
        user_id: crate::identity::types::UserId::new(format!("service:{id}")),
        session_id: crate::session::types::SessionId::new(format!("service:{id}:{slot}")),
        handle_sha256: Secret::new(String::new()).digest(),
        handle_value: Secret::new(String::new()),
        role: crate::store::AdminRole::Viewer,
        email: None,
        display_name: Some(format!("service credential {id}")),
        auth_time: st.clock.now(),
        auth_time_source: crate::store::AuthTimeSource::HopaeCompletion,
        aal: crate::session::types::Aal::One,
        provider_id: crate::provider::types::ProviderId::new("service-credential"),
    };
    Ok((
        principal,
        ServiceCaller {
            credential_id: row.credential_id,
            slot,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_ids_and_digests() {
        let rng = crate::crypto::SeededRng::new(7);
        let (token, d) = mint(&rng, "pumgye-v2");
        let (id, secret) = parse_token(token.expose()).unwrap();
        assert_eq!(id, "pumgye-v2");
        assert_eq!(digest(id, secret), d);
        assert_ne!(
            digest("pumgye-v3", secret),
            d,
            "the id is bound into the digest"
        );
        for bad in [
            "hsc1.Pumgye.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hsc1.pumgye.short",
            "hsc2.pumgye.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hsc1.-x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hsc1.pumgye.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
        ] {
            assert!(parse_token(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn only_read_routes_are_grantable() {
        for r in PUMGYE_V2_ROUTES {
            assert!(grantable(r), "{r}");
        }
        for r in [
            "POST /v1/groups/create",
            "POST /v1/groups/members/add",
            "POST /v1/users/u_x/disable",
            "PUT /v1/authentication/profiles",
            "GET /v1/users",
            "GET /v1/groups/projection/snapshot",
            "POST /v1/groups/projection/snapshot/",
            "post /v1/subjects/lifecycle",
        ] {
            assert!(!grantable(r), "{r}");
        }
        for (m, p) in READABLE {
            assert!(!super::super::auth::is_mutation(&m.parse().unwrap(), p));
        }
    }

    #[test]
    fn rate_limit_is_per_credential() {
        let l = 0xdead_usize;
        assert!(take(l, "a", 60, 2).is_ok());
        assert!(take(l, "a", 60, 2).is_ok());
        assert!(take(l, "a", 60, 2).is_err());
        assert!(take(l, "b", 60, 2).is_ok());
    }
}
