//! Reference-only native issuer resources. No inline signing seed is accepted.
use super::{
    receipt_issuer::{Configuration, Issuer, Scope},
    receipt_keys::Refused,
};
use crate::crypto::{Clock, Rng};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::Zeroizing;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeIssuer {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub identity_authority_epoch: String,
    pub public_key: String,
    pub seed_env: String,
    pub scopes: Vec<Scope>,
}
impl NativeIssuer {
    pub fn validate(&self) -> Result<Configuration, Refused> {
        let id = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        };
        if !id(&self.issuer_ref)
            || !id(&self.identity_authority_epoch)
            || self.identity_authority_epoch.len() > 96
            || !(1..=9_007_199_254_740_991).contains(&self.key_epoch)
            || self.seed_env.is_empty()
            || self.seed_env.len() > 128
            || !self
                .seed_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self.scopes.is_empty()
            || self.scopes.len() > 128
        {
            return Err(Refused);
        }
        let key: [u8; 32] = STANDARD
            .decode(&self.public_key)
            .map_err(|_| Refused)?
            .try_into()
            .map_err(|_| Refused)?;
        if ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| Refused)?
            .is_weak()
        {
            return Err(Refused);
        }
        let mut seen = std::collections::BTreeSet::new();
        for scope in &self.scopes {
            if !id(&scope.service)
                || !id(&scope.audience)
                || !seen.insert((&scope.service, &scope.audience))
            {
                return Err(Refused);
            }
        }
        Ok(Configuration {
            issuer_ref: self.issuer_ref.clone(),
            key_epoch: self.key_epoch,
            identity_authority_epoch: self.identity_authority_epoch.clone(),
            public_key: key,
            scopes: self.scopes.clone(),
        })
    }
    pub fn load(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Issuer, Refused> {
        let configuration = self.validate()?;
        let value = Zeroizing::new(env(&self.seed_env).ok_or(Refused)?);
        if value.len() != 44 {
            return Err(Refused);
        }
        let bytes = Zeroizing::new(STANDARD.decode(value.as_bytes()).map_err(|_| Refused)?);
        if bytes.len() != 32 {
            return Err(Refused);
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&bytes);
        Issuer::new(configuration, seed, clock, rng)
    }
}
/// Public receiver-owned permit descriptor; signing resources stay in Pumgye.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermitKey {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
}
/// Validates all purpose separation/duplicate constraints before persistence.
pub fn receiver_keys(
    issuer: Option<&NativeIssuer>,
    permits: &[PermitKey],
) -> Result<Vec<super::receipt_keys::Key>, Refused> {
    use super::{
        receipt::Purpose,
        receipt_keys::{Key, Registry},
    };
    if permits.len() > 63 || (!permits.is_empty() && issuer.is_none()) {
        return Err(Refused);
    }
    let mut keys = Vec::with_capacity(permits.len() + usize::from(issuer.is_some()));
    if let Some(issuer) = issuer {
        let issuer = issuer.validate()?;
        keys.push(Key {
            issuer_ref: issuer.issuer_ref,
            purpose: Purpose::Authentication,
            epoch: issuer.key_epoch,
            public_key: issuer.public_key,
        });
    }
    for permit in permits {
        if permit.public_key.len() != 44 {
            return Err(Refused);
        }
        let bytes: [u8; 32] = STANDARD
            .decode(&permit.public_key)
            .map_err(|_| Refused)?
            .try_into()
            .map_err(|_| Refused)?;
        if STANDARD.encode(bytes) != permit.public_key {
            return Err(Refused);
        }
        keys.push(Key {
            issuer_ref: permit.issuer_ref.clone(),
            purpose: Purpose::Permit,
            epoch: permit.key_epoch,
            public_key: bytes,
        });
    }
    Registry::compile(1, &keys, None)?;
    Ok(keys)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receiver_public_keys_require_native_issuer_and_independent_bounded_descriptors() {
        let auth = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let permit = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let base = serde_json::json!({"state_dir":"owned-state","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER_REFERENCE"},"apps":[{"app_id":"orders","hosts":["app.example.test"]}],"receipt_issuer":{"issuer_ref":"owned","key_epoch":1,"identity_authority_epoch":"epoch1","public_key":STANDARD.encode(auth.verifying_key().to_bytes()),"seed_env":"OWNED_RECEIPT_SEED","scopes":[{"service":"orders","audience":"orders-api"}]},"receipt_permit_keys":[{"issuer_ref":"pumgye","key_epoch":1,"public_key":STANDARD.encode(permit.verifying_key().to_bytes())}]});
        let parsed = crate::config::parse(&base.to_string()).unwrap();
        assert_eq!(
            receiver_keys(parsed.receipt_issuer.as_ref(), &parsed.receipt_permit_keys)
                .unwrap()
                .len(),
            2
        );
        for mutate in [
            |v: &mut serde_json::Value| {
                v["receipt_permit_keys"][0]["key_epoch"] = serde_json::json!(0)
            },
            |v: &mut serde_json::Value| {
                v["receipt_permit_keys"][0]["public_key"] =
                    serde_json::json!(STANDARD.encode([0; 32]))
            },
            |v: &mut serde_json::Value| {
                v["receipt_permit_keys"][0]["public_key"] =
                    v["receipt_issuer"]["public_key"].clone()
            },
            |v: &mut serde_json::Value| {
                let repeated = v["receipt_permit_keys"][0].clone();
                v["receipt_permit_keys"]
                    .as_array_mut()
                    .unwrap()
                    .push(repeated);
            },
            |v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("receipt_issuer");
            },
            |v: &mut serde_json::Value| {
                v["receipt_permit_keys"][0]["seed"] =
                    serde_json::json!("owned-inline-fixture-secret")
            },
        ] {
            let mut bad = base.clone();
            mutate(&mut bad);
            let error = crate::config::parse(&bad.to_string())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("owned-inline-fixture-secret"));
        }
    }
    #[test]
    fn startup_configuration_refuses_untrusted_scope_and_invalid_key_generations() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let base = serde_json::json!({"state_dir":"owned-state","portal":{"public_url":"https://auth.example.test"},"gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER_REFERENCE"},"apps":[{"app_id":"orders","hosts":["app.example.test"]}],"receipt_issuer":{"issuer_ref":"owned","key_epoch":1,"identity_authority_epoch":"epoch1","public_key":STANDARD.encode(signer.verifying_key().to_bytes()),"seed_env":"OWNED_RECEIPT_SEED","scopes":[{"service":"orders","audience":"orders-api"}]}});
        assert!(crate::config::parse(&base.to_string()).is_ok());
        for mutate in [
            |v: &mut serde_json::Value| v["receipt_issuer"]["key_epoch"] = serde_json::json!(0),
            |v: &mut serde_json::Value| {
                v["receipt_issuer"]["key_epoch"] = serde_json::json!(9_007_199_254_740_992u64)
            },
            |v: &mut serde_json::Value| {
                v["receipt_issuer"]["public_key"] = serde_json::json!(STANDARD.encode([0; 32]))
            },
            |v: &mut serde_json::Value| {
                v["receipt_issuer"]["scopes"][0]["service"] = serde_json::json!("undeclared")
            },
            |v: &mut serde_json::Value| {
                v["receipt_issuer"]["seed_env"] = serde_json::json!("bad reference")
            },
            |v: &mut serde_json::Value| {
                v["receipt_issuer"]["seed"] = serde_json::json!("inline-value")
            },
            |v: &mut serde_json::Value| {
                v["gateway"]["allow_unauthenticated_caller"] = serde_json::json!(true)
            },
        ] {
            let mut invalid = base.clone();
            mutate(&mut invalid);
            assert!(
                crate::config::parse(&invalid.to_string()).is_err(),
                "invalid receipt capability accepted"
            );
        }
    }

    #[test]
    fn native_resources_reject_missing_wrong_seeds_inline_secrets_and_duplicate_scopes() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let config = NativeIssuer {
            issuer_ref: "owned".into(),
            key_epoch: 1,
            identity_authority_epoch: "epoch1".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            seed_env: "OWNED_RECEIPT_SEED".into(),
            scopes: vec![Scope {
                service: "orders".into(),
                audience: "orders-api".into(),
            }],
        };
        let clock = Arc::new(crate::crypto::SystemClock);
        let rng = Arc::new(crate::crypto::OsRng);
        assert!(
            config
                .load(
                    &|_| Some(STANDARD.encode([7; 32])),
                    clock.clone(),
                    rng.clone()
                )
                .is_ok()
        );
        assert!(config.load(&|_| None, clock.clone(), rng.clone()).is_err());
        assert!(
            config
                .load(&|_| Some(STANDARD.encode([8; 32])), clock, rng)
                .is_err()
        );
        let mut duplicate = config.clone();
        duplicate.scopes.push(duplicate.scopes[0].clone());
        assert!(duplicate.validate().is_err());
        assert!(
            serde_json::from_value::<NativeIssuer>(serde_json::json!({"seed":"inline"})).is_err()
        );
    }
}
