//! Operator-supplied key references compile into an immutable in-memory keyring.
//! This module does not add a configuration/HTTP endpoint or rotate stored envelopes.
use super::seed_cipher::{Envelope, Key};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub id: String,
    pub key_env: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub active_key: String,
    pub keys: Vec<Reference>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidKeyring;
pub struct Keyring {
    active: String,
    keys: HashMap<String, Key>,
}
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keyring(<redacted>)")
    }
}
impl Keyring {
    pub fn compile(
        configuration: &Configuration,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, InvalidKeyring> {
        configuration.validate_references()?;
        let mut keys = HashMap::new();
        let mut fingerprints = HashSet::new();
        for reference in &configuration.keys {
            let value = Zeroizing::new(env(&reference.key_env).ok_or(InvalidKeyring)?);
            if value.len() != 43 {
                return Err(InvalidKeyring);
            }
            let decoded = Zeroizing::new(
                data_encoding::BASE64URL_NOPAD
                    .decode(value.as_bytes())
                    .map_err(|_| InvalidKeyring)?,
            );
            if decoded.len() != 32
                || decoded.iter().all(|b| *b == 0)
                || !fingerprints.insert(crate::crypto::sha256(&decoded))
            {
                return Err(InvalidKeyring);
            }
            let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| InvalidKeyring)?;
            keys.insert(
                reference.id.clone(),
                Key::new(reference.id.clone(), bytes).map_err(|_| InvalidKeyring)?,
            );
        }
        Ok(Self {
            active: configuration.active_key.clone(),
            keys,
        })
    }
    pub fn active(&self) -> &Key {
        self.keys.get(&self.active).expect("compiled active key")
    }
    /// Exact ID lookup only; no active-key or external-secret fallback.
    pub fn for_envelope(&self, envelope: &Envelope) -> Option<&Key> {
        self.keys.get(envelope.key_id())
    }
}
impl Configuration {
    pub fn validate_references(&self) -> Result<(), InvalidKeyring> {
        if self.keys.is_empty() || self.keys.len() > 16 {
            return Err(InvalidKeyring);
        }
        let mut ids = HashSet::new();
        let mut refs = HashSet::new();
        // Validate the whole reference set before looking up any secret.
        for reference in &self.keys {
            if reference.id.is_empty()
                || reference.id.len() > 128
                || !reference
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                || !reference
                    .key_env
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                || reference.key_env.is_empty()
                || reference.key_env.len() > 128
                || !reference
                    .key_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !ids.insert(reference.id.clone())
                || !refs.insert(reference.key_env.clone())
            {
                return Err(InvalidKeyring);
            }
        }
        if !ids.contains(&self.active_key) {
            return Err(InvalidKeyring);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::OsRng, factor::totp::Seed};
    fn config(active: &str) -> Configuration {
        Configuration {
            active_key: active.into(),
            keys: vec![
                Reference {
                    id: "old".into(),
                    key_env: "OLD_KEY".into(),
                },
                Reference {
                    id: "new".into(),
                    key_env: "NEW_KEY".into(),
                },
            ],
        }
    }
    fn env(name: &str) -> Option<String> {
        Some(data_encoding::BASE64URL_NOPAD.encode(&[if name == "OLD_KEY" { 7 } else { 8 }; 32]))
    }
    #[test]
    fn rotates_encryption_key_retains_explicit_old_decryption_and_refuses_retirement() {
        let old = Keyring::compile(&config("old"), &env).unwrap();
        let seed = Seed::from_bytes(&[9; 20]).unwrap();
        let envelope = old.active().seal(&seed, "u_a", "e_1", &OsRng).unwrap();
        let rotated = Keyring::compile(&config("new"), &env).unwrap();
        assert!(
            rotated
                .for_envelope(&envelope)
                .unwrap()
                .open(&envelope, "u_a", "e_1")
                .is_ok()
        );
        assert!(rotated.active().open(&envelope, "u_a", "e_1").is_err());
        let mut retired = config("new");
        retired.keys.remove(0);
        assert!(
            Keyring::compile(&retired, &env)
                .unwrap()
                .for_envelope(&envelope)
                .is_none()
        );
        assert_eq!(format!("{rotated:?}"), "Keyring(<redacted>)");
    }
    #[test]
    fn rejects_invalid_references_and_material_without_disclosing_values() {
        assert_eq!(
            Keyring::compile(&config("missing"), &|_| panic!(
                "must not resolve malformed references"
            ))
            .err(),
            Some(InvalidKeyring)
        );
        let mut duplicate = config("old");
        duplicate.keys.push(duplicate.keys[0].clone());
        assert_eq!(
            Keyring::compile(&duplicate, &|_| panic!(
                "must not resolve malformed references"
            ))
            .err(),
            Some(InvalidKeyring)
        );
        assert!(Keyring::compile(&config("old"), &|_| None).is_err());
        for bad in [
            "".into(),
            "x".repeat(44),
            data_encoding::BASE64URL_NOPAD.encode(&[0; 32]),
            data_encoding::BASE64URL_NOPAD.encode(&[7; 32]),
        ] {
            assert!(Keyring::compile(&config("old"), &|_| Some(bad.clone())).is_err());
        }
        let mut invalid = config("old");
        invalid.keys[0].key_env = "bad/reference".into();
        assert!(
            Keyring::compile(&invalid, &|_| panic!(
                "must not resolve malformed references"
            ))
            .is_err()
        );
    }
}
