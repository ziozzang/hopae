//! ID token validation (OpenID Connect Core 1.0 section 3.1.3.7), split into
//! steps so each is testable alone and the order is fixed:
//!
//! 1. structure and header: three segments, `alg` from the allowlist (never
//!    `none`, never HMAC), `typ` when configured, no `crit`;
//! 2. signature, with the key chosen by `kid` (see [`super::jwks`]);
//! 3. claims, only ever read from the verified payload: `iss`, `aud`, `azp`,
//!    `exp`, `nbf`, `iat`, `nonce`, `sub`.
//!
//! Time comes from an injected `Timestamp`; nothing here reads the wall clock.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::jwks::parse_alg;
use crate::crypto::{Timestamp, ct_eq};
use crate::provider::types::ProviderError;

/// Largest compact token accepted.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Clock skew allowed on `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: i64 = 60;
/// Longest `sub` (Core 2: at most 255 ASCII characters).
const MAX_SUB_BYTES: usize = 255;

/// The parts of the JOSE header the verifier uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHeader {
    pub alg: Algorithm,
    pub kid: Option<String>,
}

/// What the callback is expected to prove.
pub struct Expect<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub now: Timestamp,
}

fn segments(token: &str) -> Result<(&str, &str, &str), ProviderError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(ProviderError::ProviderResponseInvalid);
    }
    let mut it = token.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() => Ok((h, p, s)),
        _ => Err(ProviderError::ProviderResponseInvalid),
    }
}

fn json_segment(seg: &str) -> Result<Value, ProviderError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(seg)
        .map_err(|_| ProviderError::ProviderResponseInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::ProviderResponseInvalid)
}

/// Step 1. A token whose segments do not decode is a malformed provider
/// response; a token that decodes but names a forbidden algorithm, lacks the
/// required `typ` or carries `crit` has an invalid header.
pub fn parse_header(
    token: &str,
    allowed: &[Algorithm],
    required_typ: Option<&str>,
) -> Result<TokenHeader, ProviderError> {
    let (h, _, _) = segments(token)?;
    let header = json_segment(h)?;
    let obj = header
        .as_object()
        .ok_or(ProviderError::ProviderResponseInvalid)?;
    let alg_name = obj
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidTokenHeader)?;
    // `none`, `HS*` and anything unknown are not in the table at all.
    let alg = parse_alg(alg_name).ok_or(ProviderError::InvalidTokenHeader)?;
    if !allowed.contains(&alg) {
        return Err(ProviderError::InvalidTokenHeader);
    }
    if obj.contains_key("crit") {
        return Err(ProviderError::InvalidTokenHeader);
    }
    if let Some(want) = required_typ {
        let got = obj.get("typ").and_then(Value::as_str);
        if !got.is_some_and(|t| t.eq_ignore_ascii_case(want)) {
            return Err(ProviderError::InvalidTokenHeader);
        }
    }
    let kid = match obj.get("kid") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 256 => Some(s.clone()),
        Some(_) => return Err(ProviderError::InvalidTokenHeader),
    };
    Ok(TokenHeader { alg, kid })
}

/// The unverified `iss`, used only to pick the more specific error
/// (`invalid_issuer`) for a token that is rejected either way.
pub fn peek_issuer(token: &str) -> Option<String> {
    let (_, p, _) = segments(token).ok()?;
    json_segment(p)
        .ok()?
        .get("iss")?
        .as_str()
        .map(str::to_string)
}

/// Step 2. Verifies the signature with exactly the header's algorithm and
/// returns the payload. No claim is checked here.
pub fn verify_signature(
    token: &str,
    header: &TokenHeader,
    key: &DecodingKey,
) -> Result<Value, ProviderError> {
    let mut v = Validation::new(header.alg);
    v.required_spec_claims.clear();
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    v.leeway = 0;
    match jsonwebtoken::decode::<Value>(token, key, &v) {
        Ok(data) => Ok(data.claims),
        Err(e) => match e.kind() {
            jsonwebtoken::errors::ErrorKind::Json(_) | jsonwebtoken::errors::ErrorKind::Utf8(_) => {
                Err(ProviderError::ProviderResponseInvalid)
            }
            _ => Err(ProviderError::InvalidSignature),
        },
    }
}

/// A NumericDate as whole seconds (fractions are floored).
fn numeric_date(v: &Value) -> Option<i64> {
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    let f = v.as_f64()?;
    (f.is_finite() && f.abs() < 1e15).then(|| f.floor() as i64)
}

/// Step 3. `claims` must come from [`verify_signature`].
pub fn validate_claims(claims: &Value, e: &Expect<'_>) -> Result<(), ProviderError> {
    let obj = claims
        .as_object()
        .ok_or(ProviderError::ProviderResponseInvalid)?;

    match obj.get("iss").and_then(Value::as_str) {
        Some(iss) if iss == e.issuer => {}
        _ => return Err(ProviderError::InvalidIssuer),
    }

    // The client must be the only audience: this client trusts no other
    // audience (Core 3.1.3.7, rules 2 and 3).
    let aud_ok = match obj.get("aud") {
        Some(Value::String(a)) => a == e.client_id,
        Some(Value::Array(a)) => !a.is_empty() && a.iter().all(|x| x.as_str() == Some(e.client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(ProviderError::InvalidAudience);
    }
    match obj.get("azp") {
        None | Some(Value::Null) => {}
        Some(Value::String(a)) if a == e.client_id => {}
        Some(_) => return Err(ProviderError::InvalidAudience),
    }

    let now = e.now.secs();
    let exp = obj
        .get("exp")
        .and_then(numeric_date)
        .ok_or(ProviderError::ProviderResponseInvalid)?;
    if exp.saturating_add(LEEWAY_SECS) <= now {
        return Err(ProviderError::TokenExpired);
    }
    if let Some(nbf) = obj.get("nbf") {
        let nbf = numeric_date(nbf).ok_or(ProviderError::ProviderResponseInvalid)?;
        if nbf > now.saturating_add(LEEWAY_SECS) {
            return Err(ProviderError::TokenExpired);
        }
    }
    let iat = obj
        .get("iat")
        .and_then(numeric_date)
        .ok_or(ProviderError::ProviderResponseInvalid)?;
    if iat > now.saturating_add(LEEWAY_SECS) {
        return Err(ProviderError::TokenExpired);
    }

    match obj.get("nonce").and_then(Value::as_str) {
        Some(n) if !e.nonce.is_empty() && ct_eq(n.as_bytes(), e.nonce.as_bytes()) => {}
        _ => return Err(ProviderError::InvalidNonce),
    }

    match obj.get("sub").and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.len() <= MAX_SUB_BYTES => {}
        _ => return Err(ProviderError::ProviderResponseInvalid),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISS: &str = "https://idp.example.test";
    const CID: &str = "client-1";

    fn exp(now: i64) -> Expect<'static> {
        Expect {
            issuer: ISS,
            client_id: CID,
            nonce: "n-1",
            now: Timestamp(now * 1000),
        }
    }

    fn good(now: i64) -> Value {
        json!({"iss": ISS, "aud": CID, "sub": "s", "exp": now + 300, "iat": now, "nonce": "n-1"})
    }

    fn with(mut v: Value, k: &str, val: Value) -> Value {
        v[k] = val;
        v
    }

    fn without(mut v: Value, k: &str) -> Value {
        v.as_object_mut().unwrap().remove(k);
        v
    }

    fn check(v: &Value) -> Result<(), ProviderError> {
        validate_claims(v, &exp(1_000_000))
    }

    #[test]
    fn accepts_a_good_token() {
        assert!(check(&good(1_000_000)).is_ok());
        // Fractional dates are accepted.
        assert!(check(&with(good(1_000_000), "exp", json!(1_000_300.7))).is_ok());
    }

    #[test]
    fn issuer_must_match_exactly() {
        for iss in [
            json!("https://idp.example.test/"),
            json!("HTTPS://idp.example.test"),
            json!(5),
            Value::Null,
        ] {
            assert!(matches!(
                check(&with(good(1_000_000), "iss", iss)),
                Err(ProviderError::InvalidIssuer)
            ));
        }
        assert!(matches!(
            check(&without(good(1_000_000), "iss")),
            Err(ProviderError::InvalidIssuer)
        ));
    }

    #[test]
    fn audience_and_azp() {
        let g = good(1_000_000);
        for aud in [
            json!("other"),
            json!(["client-1", "other"]),
            json!([]),
            json!(5),
            json!(["other"]),
        ] {
            assert!(matches!(
                check(&with(g.clone(), "aud", aud)),
                Err(ProviderError::InvalidAudience)
            ));
        }
        assert!(matches!(
            check(&without(g.clone(), "aud")),
            Err(ProviderError::InvalidAudience)
        ));
        assert!(check(&with(g.clone(), "aud", json!(["client-1"]))).is_ok());
        assert!(check(&with(g.clone(), "azp", json!("client-1"))).is_ok());
        assert!(matches!(
            check(&with(g.clone(), "azp", json!("other"))),
            Err(ProviderError::InvalidAudience)
        ));
        assert!(matches!(
            check(&with(g, "azp", json!(1))),
            Err(ProviderError::InvalidAudience)
        ));
    }

    #[test]
    fn expiry_and_issue_time_with_leeway() {
        let now = 1_000_000;
        let g = good(now);
        // exp 59 s ago is inside the leeway, 60 s ago is not.
        assert!(check(&with(g.clone(), "exp", json!(now - 59))).is_ok());
        assert!(matches!(
            check(&with(g.clone(), "exp", json!(now - 60))),
            Err(ProviderError::TokenExpired)
        ));
        // iat 60 s ahead is inside the leeway, 61 s ahead is not.
        assert!(check(&with(g.clone(), "iat", json!(now + 60))).is_ok());
        assert!(matches!(
            check(&with(g.clone(), "iat", json!(now + 61))),
            Err(ProviderError::TokenExpired)
        ));
        assert!(matches!(
            check(&with(g.clone(), "nbf", json!(now + 61))),
            Err(ProviderError::TokenExpired)
        ));
        assert!(check(&with(g.clone(), "nbf", json!(now + 60))).is_ok());
        // Required and well-typed.
        assert!(matches!(
            check(&without(g.clone(), "exp")),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&without(g.clone(), "iat")),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&with(g.clone(), "exp", json!("soon"))),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&with(g, "exp", json!(null))),
            Err(ProviderError::ProviderResponseInvalid)
        ));
    }

    #[test]
    fn nonce_is_required_and_exact() {
        let g = good(1_000_000);
        assert!(matches!(
            check(&with(g.clone(), "nonce", json!("n-2"))),
            Err(ProviderError::InvalidNonce)
        ));
        assert!(matches!(
            check(&with(g.clone(), "nonce", json!(""))),
            Err(ProviderError::InvalidNonce)
        ));
        assert!(matches!(
            check(&with(g.clone(), "nonce", json!(1))),
            Err(ProviderError::InvalidNonce)
        ));
        assert!(matches!(
            check(&without(g.clone(), "nonce")),
            Err(ProviderError::InvalidNonce)
        ));
        // An empty expected nonce can never be satisfied.
        let e = Expect {
            nonce: "",
            ..exp(1_000_000)
        };
        assert!(matches!(
            validate_claims(&with(g, "nonce", json!("")), &e),
            Err(ProviderError::InvalidNonce)
        ));
    }

    #[test]
    fn subject_is_required_and_bounded() {
        let g = good(1_000_000);
        assert!(matches!(
            check(&without(g.clone(), "sub")),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&with(g.clone(), "sub", json!(""))),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&with(g.clone(), "sub", json!(12))),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(matches!(
            check(&with(g.clone(), "sub", json!("x".repeat(256)))),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        assert!(check(&with(g, "sub", json!("x".repeat(255)))).is_ok());
    }

    fn token_with_header(h: &Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(h.to_string()),
            URL_SAFE_NO_PAD.encode(r#"{"iss":"x"}"#),
            "c2ln"
        )
    }

    #[test]
    fn header_rules() {
        let allowed = [Algorithm::RS256];
        let ok = parse_header(
            &token_with_header(&json!({"alg":"RS256","kid":"k","typ":"JWT"})),
            &allowed,
            None,
        )
        .unwrap();
        assert_eq!(
            ok,
            TokenHeader {
                alg: Algorithm::RS256,
                kid: Some("k".into())
            }
        );
        for h in [
            json!({"alg":"none"}),
            json!({"alg":"None"}),
            json!({"alg":"HS256"}),
            json!({"alg":"HS512"}),
            json!({"alg":"RS384"}),
            json!({"alg":"EdDSA"}),
            json!({"kid":"k"}),
            json!({"alg":5}),
            json!({"alg":"RS256","crit":["exp"]}),
            json!({"alg":"RS256","kid":7}),
            json!({"alg":"RS256","kid":""}),
        ] {
            assert!(
                matches!(
                    parse_header(&token_with_header(&h), &allowed, None),
                    Err(ProviderError::InvalidTokenHeader)
                ),
                "{h}"
            );
        }
        // typ is enforced only when configured, case-insensitively.
        let h = json!({"alg":"RS256","typ":"at+jwt"});
        assert!(parse_header(&token_with_header(&h), &allowed, None).is_ok());
        assert!(parse_header(&token_with_header(&h), &allowed, Some("AT+JWT")).is_ok());
        assert!(matches!(
            parse_header(
                &token_with_header(&json!({"alg":"RS256","typ":"JWT"})),
                &allowed,
                Some("at+jwt")
            ),
            Err(ProviderError::InvalidTokenHeader)
        ));
        assert!(matches!(
            parse_header(
                &token_with_header(&json!({"alg":"RS256"})),
                &allowed,
                Some("at+jwt")
            ),
            Err(ProviderError::InvalidTokenHeader)
        ));
    }

    #[test]
    fn malformed_structure_is_a_response_error() {
        let allowed = [Algorithm::RS256];
        for t in ["", "a", "a.b", "a.b.c.d", "!!!.@@@.###", "..", "e30.e30"] {
            assert!(
                matches!(
                    parse_header(t, &allowed, None),
                    Err(ProviderError::ProviderResponseInvalid)
                ),
                "{t}"
            );
        }
        let huge = format!("a.b.{}", "c".repeat(MAX_TOKEN_BYTES));
        assert!(matches!(
            parse_header(&huge, &allowed, None),
            Err(ProviderError::ProviderResponseInvalid)
        ));
        // A header that is JSON but not an object.
        let t = format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode("[1]"));
        assert!(matches!(
            parse_header(&t, &allowed, None),
            Err(ProviderError::ProviderResponseInvalid)
        ));
    }

    #[test]
    fn peek_issuer_reads_without_trusting() {
        let t = format!(
            "e30.{}.c2ln",
            URL_SAFE_NO_PAD.encode(r#"{"iss":"https://other"}"#)
        );
        assert_eq!(peek_issuer(&t).as_deref(), Some("https://other"));
        assert_eq!(peek_issuer("garbage"), None);
    }
}
