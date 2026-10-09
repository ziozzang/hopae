//! JWKS parsing and key selection. Only asymmetric signature keys are kept:
//! symmetric (`oct`) keys and encryption keys are dropped at parse time, so an
//! HMAC "key confusion" token can never find a key to verify against.

use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey};
use serde_json::Value;

use crate::provider::types::ProviderError;

/// Most keys read from one document.
const MAX_KEYS: usize = 64;

/// Algorithms an ID token may use: asymmetric signatures only. `none` and the
/// HMAC family are not representable here by construction.
pub const SUPPORTED_ALGS: [Algorithm; 8] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

pub fn parse_alg(name: &str) -> Option<Algorithm> {
    SUPPORTED_ALGS.into_iter().find(|a| alg_name(*a) == name)
}

pub fn alg_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        _ => "unsupported",
    }
}

pub struct KeyEntry {
    pub kid: Option<String>,
    /// The key's declared `alg`, when it declares one.
    pub alg: Option<Algorithm>,
    pub family: AlgorithmFamily,
    /// EC curve name for `ES*` checks.
    pub crv: Option<String>,
    pub key: DecodingKey,
}

pub struct KeySet {
    pub keys: Vec<KeyEntry>,
}

/// What `select` found for a token header.
pub enum Selection<'a> {
    /// Candidates to try (usually one).
    Candidates(Vec<&'a KeyEntry>),
    /// The header names a `kid` the set does not contain.
    UnknownKid,
    /// No `kid` in the header and more than one possible key.
    Ambiguous,
    /// No `kid`, no key usable for this algorithm.
    NoKey,
}

impl KeySet {
    pub fn parse(bytes: &[u8]) -> Result<KeySet, ProviderError> {
        let doc: Value =
            serde_json::from_slice(bytes).map_err(|_| ProviderError::ProviderResponseInvalid)?;
        let arr = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(ProviderError::ProviderResponseInvalid)?;
        let mut keys = Vec::new();
        for item in arr.iter().take(MAX_KEYS) {
            if let Some(k) = parse_key(item) {
                keys.push(k);
            }
        }
        if keys.is_empty() {
            return Err(ProviderError::ProviderResponseInvalid);
        }
        Ok(KeySet { keys })
    }

    pub fn select(&self, alg: Algorithm, kid: Option<&str>) -> Selection<'_> {
        let usable = |k: &&KeyEntry| {
            k.family == alg.family()
                && k.alg.is_none_or(|a| a == alg)
                && match (alg, k.crv.as_deref()) {
                    (Algorithm::ES256, c) => c == Some("P-256"),
                    (Algorithm::ES384, c) => c == Some("P-384"),
                    _ => true,
                }
        };
        match kid {
            Some(kid) => {
                let named: Vec<&KeyEntry> = self
                    .keys
                    .iter()
                    .filter(|k| k.kid.as_deref() == Some(kid))
                    .filter(usable)
                    .collect();
                if named.is_empty() {
                    Selection::UnknownKid
                } else {
                    Selection::Candidates(named)
                }
            }
            None => {
                let mut all = self.keys.iter().filter(usable);
                match (all.next(), all.next()) {
                    (None, _) => Selection::NoKey,
                    (Some(k), None) => Selection::Candidates(vec![k]),
                    (Some(_), Some(_)) => Selection::Ambiguous,
                }
            }
        }
    }
}

fn parse_key(v: &Value) -> Option<KeyEntry> {
    let o = v.as_object()?;
    let s = |k: &str| o.get(k).and_then(Value::as_str);
    if let Some(u) = o.get("use")
        && u.as_str() != Some("sig")
    {
        return None;
    }
    if let Some(ops) = o.get("key_ops") {
        let ok = ops
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x.as_str() == Some("verify")));
        if !ok {
            return None;
        }
    }
    let alg = match s("alg") {
        Some(name) => Some(parse_alg(name)?),
        None => None,
    };
    let kid = s("kid").map(str::to_string);
    let (key, family, crv) = match s("kty")? {
        "RSA" => (
            DecodingKey::from_rsa_components(s("n")?, s("e")?).ok()?,
            AlgorithmFamily::Rsa,
            None,
        ),
        "EC" => {
            let crv = s("crv")?.to_string();
            if crv != "P-256" && crv != "P-384" {
                return None;
            }
            (
                DecodingKey::from_ec_components(s("x")?, s("y")?).ok()?,
                AlgorithmFamily::Ec,
                Some(crv),
            )
        }
        _ => return None,
    };
    Some(KeyEntry {
        kid,
        alg,
        family,
        crv,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";

    fn set(extra: &str) -> Vec<u8> {
        format!(r#"{{"keys":[{{"kty":"RSA","n":"{N}","e":"AQAB"{extra}}}]}}"#).into_bytes()
    }

    #[test]
    fn symmetric_and_encryption_keys_are_dropped() {
        let doc = format!(
            r#"{{"keys":[{{"kty":"oct","k":"c2VjcmV0","kid":"h"}},{{"kty":"RSA","use":"enc","n":"{N}","e":"AQAB","kid":"e"}}]}}"#
        );
        assert!(matches!(
            KeySet::parse(doc.as_bytes()),
            Err(ProviderError::ProviderResponseInvalid)
        ));
    }

    #[test]
    fn selection_rules() {
        let ks = KeySet::parse(&set(r#","kid":"a""#)).unwrap();
        assert!(
            matches!(ks.select(Algorithm::RS256, Some("a")), Selection::Candidates(c) if c.len() == 1)
        );
        assert!(matches!(
            ks.select(Algorithm::RS256, Some("b")),
            Selection::UnknownKid
        ));
        // One key and no kid: usable. A symmetric or EC algorithm finds nothing.
        assert!(matches!(
            ks.select(Algorithm::RS256, None),
            Selection::Candidates(_)
        ));
        assert!(matches!(
            ks.select(Algorithm::ES256, None),
            Selection::NoKey
        ));
        let two = format!(
            r#"{{"keys":[{{"kty":"RSA","n":"{N}","e":"AQAB","kid":"a"}},{{"kty":"RSA","n":"{N}","e":"AQAB","kid":"b"}}]}}"#
        );
        let ks = KeySet::parse(two.as_bytes()).unwrap();
        assert!(matches!(
            ks.select(Algorithm::RS256, None),
            Selection::Ambiguous
        ));
    }

    #[test]
    fn declared_key_alg_must_match() {
        let ks = KeySet::parse(&set(r#","kid":"a","alg":"RS384""#)).unwrap();
        assert!(matches!(
            ks.select(Algorithm::RS256, Some("a")),
            Selection::UnknownKid
        ));
        assert!(matches!(
            ks.select(Algorithm::RS384, Some("a")),
            Selection::Candidates(_)
        ));
    }

    #[test]
    fn alg_names_round_trip_and_exclude_none_and_hmac() {
        for a in SUPPORTED_ALGS {
            assert_eq!(parse_alg(alg_name(a)), Some(a));
        }
        for bad in ["none", "None", "HS256", "HS512", "EdDSA", ""] {
            assert_eq!(parse_alg(bad), None);
        }
    }
}
