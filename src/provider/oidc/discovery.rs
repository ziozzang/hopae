//! The discovery document and the cache discipline shared with the JWKS:
//! hard deadline 24 h, refresh at half-life, exponential backoff 1 s to 60 s
//! after a failure (ADR-0010). The cache never serves a value older than the
//! hard deadline.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use serde_json::Value;

use super::http::endpoint_allowed;
use super::jwks::{SUPPORTED_ALGS, parse_alg};
use crate::crypto::Timestamp;
use crate::provider::types::ProviderError;

/// A cached value is never used past this age.
pub const HARD_DEADLINE: Duration = Duration::from_secs(24 * 3600);
/// Age at which a refresh is attempted in the background.
pub const HALF_LIFE: Duration = Duration::from_secs(12 * 3600);
const BACKOFF_MAX_SECS: u64 = 60;

/// How the client authenticates at the token endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenAuth {
    Basic,
    Post,
}

#[derive(Debug)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: url::Url,
    pub token_endpoint: url::Url,
    pub jwks_uri: url::Url,
    pub userinfo_endpoint: Option<url::Url>,
    /// Algorithms an ID token may use for this provider: the provider's
    /// advertised set intersected with the asymmetric algorithms this client
    /// implements (RS256 when the document is silent).
    pub algs: Vec<Algorithm>,
    pub token_auth: TokenAuth,
}

/// `<issuer>/.well-known/openid-configuration` (OpenID Connect Discovery 4).
pub fn discovery_url(issuer: &str) -> Option<url::Url> {
    let u = url::Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
    .ok()?;
    endpoint_allowed(&u).then_some(u)
}

fn endpoint(doc: &Value, key: &str) -> Result<url::Url, ProviderError> {
    let s = doc
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ProviderError::ProviderResponseInvalid)?;
    let u = url::Url::parse(s).map_err(|_| ProviderError::ProviderResponseInvalid)?;
    if endpoint_allowed(&u) {
        Ok(u)
    } else {
        Err(ProviderError::ProviderResponseInvalid)
    }
}

impl Discovery {
    /// Parse a discovery document. `issuer` must equal the configured issuer
    /// exactly (OpenID Connect Discovery 4.3).
    pub fn parse(bytes: &[u8], configured_issuer: &str) -> Result<Discovery, ProviderError> {
        let doc: Value =
            serde_json::from_slice(bytes).map_err(|_| ProviderError::ProviderResponseInvalid)?;
        if !doc.is_object() {
            return Err(ProviderError::ProviderResponseInvalid);
        }
        match doc.get("issuer").and_then(Value::as_str) {
            Some(i) if i == configured_issuer => {}
            Some(_) => return Err(ProviderError::DiscoveryIssuerMismatch),
            None => return Err(ProviderError::ProviderResponseInvalid),
        }
        let algs = match doc.get("id_token_signing_alg_values_supported") {
            None | Some(Value::Null) => vec![Algorithm::RS256],
            Some(Value::Array(a)) => {
                let set: Vec<Algorithm> = SUPPORTED_ALGS
                    .into_iter()
                    .filter(|alg| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .any(|n| parse_alg(n) == Some(*alg))
                    })
                    .collect();
                if set.is_empty() {
                    return Err(ProviderError::ProviderResponseInvalid);
                }
                set
            }
            Some(_) => return Err(ProviderError::ProviderResponseInvalid),
        };
        let token_auth = match doc
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
        {
            None => TokenAuth::Basic,
            Some(m) => {
                let has = |n: &str| m.iter().any(|x| x.as_str() == Some(n));
                if has("client_secret_basic") || !has("client_secret_post") {
                    TokenAuth::Basic
                } else {
                    TokenAuth::Post
                }
            }
        };
        let userinfo_endpoint = match doc.get("userinfo_endpoint") {
            None | Some(Value::Null) => None,
            Some(_) => Some(endpoint(&doc, "userinfo_endpoint")?),
        };
        Ok(Discovery {
            issuer: configured_issuer.to_string(),
            authorization_endpoint: endpoint(&doc, "authorization_endpoint")?,
            token_endpoint: endpoint(&doc, "token_endpoint")?,
            jwks_uri: endpoint(&doc, "jwks_uri")?,
            userinfo_endpoint,
            algs,
            token_auth,
        })
    }
}

/// One cached remote document with its clock discipline.
pub struct Cache<T> {
    value: Option<Arc<T>>,
    fetched_at: Timestamp,
    /// Time of the latest fetch attempt, successful or not.
    last_attempt: Option<Timestamp>,
    failures: u32,
    next_attempt: Timestamp,
    /// Reason code of the latest failure, cleared by a success.
    last_error: Option<&'static str>,
}

impl<T> Cache<T> {
    pub fn empty() -> Cache<T> {
        Cache {
            value: None,
            fetched_at: Timestamp(0),
            last_attempt: None,
            failures: 0,
            next_attempt: Timestamp(0),
            last_error: None,
        }
    }

    /// The value, only while younger than the hard deadline.
    pub fn valid(&self, now: Timestamp) -> Option<Arc<T>> {
        let v = self.value.as_ref()?;
        (now.since(self.fetched_at) < HARD_DEADLINE && now >= self.fetched_at).then(|| v.clone())
    }

    pub fn fetched_at(&self) -> Timestamp {
        self.fetched_at
    }

    pub fn last_attempt(&self) -> Option<Timestamp> {
        self.last_attempt
    }

    pub fn last_error(&self) -> Option<&'static str> {
        self.last_error
    }

    /// A refresh is wanted: nothing usable, or past half-life.
    pub fn refresh_due(&self, now: Timestamp) -> bool {
        match self.valid(now) {
            None => true,
            Some(_) => now.since(self.fetched_at) >= HALF_LIFE,
        }
    }

    /// Backoff gate: false while the retry delay after the last failure runs.
    pub fn may_attempt(&self, now: Timestamp) -> bool {
        now >= self.next_attempt
    }

    pub fn record_ok(&mut self, value: Arc<T>, now: Timestamp) {
        self.value = Some(value);
        self.fetched_at = now;
        self.last_attempt = Some(now);
        self.failures = 0;
        self.next_attempt = Timestamp(0);
        self.last_error = None;
    }

    /// A failed attempt. The previous value, if any, is kept (it still obeys
    /// the hard deadline in [`Cache::valid`]).
    pub fn record_err(&mut self, now: Timestamp, reason: &'static str) {
        self.failures = self.failures.saturating_add(1);
        let exp = (self.failures - 1).min(6);
        let secs = (1u64 << exp).min(BACKOFF_MAX_SECS);
        self.next_attempt = now.add(Duration::from_secs(secs));
        self.last_attempt = Some(now);
        self.last_error = Some(reason);
    }

    /// Drop the value (the document it was fetched from changed).
    pub fn clear_value(&mut self) {
        self.value = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISS: &str = "https://idp.example.test";

    fn doc() -> Value {
        json!({
            "issuer": ISS,
            "authorization_endpoint": "https://idp.example.test/auth",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks",
            "userinfo_endpoint": "https://idp.example.test/userinfo",
            "id_token_signing_alg_values_supported": ["RS256", "HS256", "none"],
        })
    }

    fn parse(v: &Value) -> Result<Discovery, ProviderError> {
        Discovery::parse(v.to_string().as_bytes(), ISS)
    }

    #[test]
    fn accepts_a_good_document_and_filters_algorithms() {
        let d = parse(&doc()).unwrap();
        assert_eq!(d.algs, vec![Algorithm::RS256]);
        assert_eq!(d.token_auth, TokenAuth::Basic);
        assert!(d.userinfo_endpoint.is_some());
    }

    #[test]
    fn issuer_must_equal_the_configured_one_exactly() {
        for iss in [
            "https://idp.example.test/",
            "https://other.example.test",
            "HTTPS://idp.example.test",
        ] {
            let mut d = doc();
            d["issuer"] = json!(iss);
            assert!(
                matches!(parse(&d), Err(ProviderError::DiscoveryIssuerMismatch)),
                "{iss}"
            );
        }
        let mut d = doc();
        d.as_object_mut().unwrap().remove("issuer");
        assert!(matches!(
            parse(&d),
            Err(ProviderError::ProviderResponseInvalid)
        ));
    }

    #[test]
    fn endpoints_must_be_present_and_safe() {
        for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut d = doc();
            d.as_object_mut().unwrap().remove(key);
            assert!(parse(&d).is_err(), "{key} missing");
            let mut d = doc();
            d[key] = json!("http://evil.example.org/x");
            assert!(parse(&d).is_err(), "{key} plain http");
        }
        let mut d = doc();
        d["userinfo_endpoint"] = json!("file:///etc/passwd");
        assert!(parse(&d).is_err());
    }

    #[test]
    fn algorithm_defaults_and_empty_intersection() {
        let mut d = doc();
        d.as_object_mut()
            .unwrap()
            .remove("id_token_signing_alg_values_supported");
        assert_eq!(parse(&d).unwrap().algs, vec![Algorithm::RS256]);
        let mut d = doc();
        d["id_token_signing_alg_values_supported"] = json!(["HS256", "none"]);
        assert!(parse(&d).is_err());
        let mut d = doc();
        d["id_token_signing_alg_values_supported"] = json!(["ES256", "RS256", "PS256"]);
        assert_eq!(
            parse(&d).unwrap().algs,
            vec![Algorithm::RS256, Algorithm::PS256, Algorithm::ES256]
        );
    }

    #[test]
    fn token_auth_follows_the_advertised_methods() {
        let mut d = doc();
        d["token_endpoint_auth_methods_supported"] = json!(["client_secret_post"]);
        assert_eq!(parse(&d).unwrap().token_auth, TokenAuth::Post);
        d["token_endpoint_auth_methods_supported"] =
            json!(["client_secret_post", "client_secret_basic"]);
        assert_eq!(parse(&d).unwrap().token_auth, TokenAuth::Basic);
    }

    #[test]
    fn cache_hard_deadline_half_life_and_backoff() {
        let t0 = Timestamp(1_000_000_000);
        let mut c: Cache<u8> = Cache::empty();
        assert!(c.valid(t0).is_none());
        assert!(c.refresh_due(t0));
        c.record_ok(Arc::new(1), t0);
        assert!(
            c.valid(t0.add(Duration::from_secs(24 * 3600 - 1)))
                .is_some()
        );
        assert!(c.valid(t0.add(Duration::from_secs(24 * 3600))).is_none());
        assert!(!c.refresh_due(t0.add(Duration::from_secs(12 * 3600 - 1))));
        assert!(c.refresh_due(t0.add(Duration::from_secs(12 * 3600))));
        // Failures keep the value but back off 1, 2, 4, ... 60 s.
        let mut now = t0.add(Duration::from_secs(12 * 3600));
        let mut seen = Vec::new();
        for _ in 0..9 {
            c.record_err(now, "x");
            let mut d = 0;
            while !c.may_attempt(now.add(Duration::from_secs(d))) {
                d += 1;
            }
            seen.push(d);
            now = now.add(Duration::from_secs(d));
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert!(
            c.valid(now).is_some(),
            "failed refreshes keep the old value until the deadline"
        );
        c.record_ok(Arc::new(2), now);
        assert!(c.may_attempt(now));
        assert_eq!(c.last_error(), None);
    }

    #[test]
    fn discovery_url_appends_the_well_known_path() {
        assert_eq!(
            discovery_url("https://accounts.google.com")
                .unwrap()
                .as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://idp.example.test/tenant/")
                .unwrap()
                .as_str(),
            "https://idp.example.test/tenant/.well-known/openid-configuration"
        );
        assert!(discovery_url("http://example.org").is_none());
    }
}
