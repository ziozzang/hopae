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
#[cfg(test)]
mod tests {
    use super::*;
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
