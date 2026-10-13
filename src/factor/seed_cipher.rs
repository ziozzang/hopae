//! Authenticated seed envelopes. Key loading, keyring rotation and storage integration are separate.
use super::totp::Seed;
use crate::crypto::Rng;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

pub struct Key {
    id: String,
    bytes: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    version: u8,
    key_id: String,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Envelope(<redacted>)")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidEnvelope;
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn associated_data(key: &str, user: &str, enrollment: &str) -> Result<Vec<u8>, InvalidEnvelope> {
    if ![key, user, enrollment].into_iter().all(identifier) {
        return Err(InvalidEnvelope);
    }
    let mut data = b"hopae/totp-seed/v1".to_vec();
    for value in [key, user, enrollment] {
        data.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value.as_bytes());
    }
    Ok(data)
}
impl Key {
    pub fn new(id: String, bytes: [u8; 32]) -> Result<Self, InvalidEnvelope> {
        let bytes = Zeroizing::new(bytes);
        if !identifier(&id) {
            return Err(InvalidEnvelope);
        }
        Ok(Self { id, bytes })
    }
    pub fn seal(
        &self,
        seed: &Seed,
        user: &str,
        enrollment: &str,
        rng: &dyn Rng,
    ) -> Result<Envelope, InvalidEnvelope> {
        let aad = associated_data(&self.id, user, enrollment)?;
        let mut nonce = [0; 24];
        rng.fill(&mut nonce);
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.bytes.as_ref()).map_err(|_| InvalidEnvelope)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: seed.bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| InvalidEnvelope)?;
        Ok(Envelope {
            version: 1,
            key_id: self.id.clone(),
            nonce,
            ciphertext,
        })
    }
    pub fn open(
        &self,
        envelope: &Envelope,
        user: &str,
        enrollment: &str,
    ) -> Result<Seed, InvalidEnvelope> {
        if envelope.version != 1
            || envelope.key_id != self.id
            || !(36..=144).contains(&envelope.ciphertext.len())
        {
            return Err(InvalidEnvelope);
        }
        let aad = associated_data(&self.id, user, enrollment)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.bytes.as_ref()).map_err(|_| InvalidEnvelope)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| InvalidEnvelope)?,
        );
        Seed::from_bytes(&plaintext).ok_or(InvalidEnvelope)
    }
}
impl Envelope {
    /// Bounded parsing for persisted envelopes. No raw seed is serialized.
    pub fn from_json(value: &str) -> Result<Self, InvalidEnvelope> {
        if value.len() > 1024 {
            return Err(InvalidEnvelope);
        }
        let envelope: Self = serde_json::from_str(value).map_err(|_| InvalidEnvelope)?;
        if envelope.version != 1
            || !identifier(&envelope.key_id)
            || !(36..=144).contains(&envelope.ciphertext.len())
        {
            return Err(InvalidEnvelope);
        }
        Ok(envelope)
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::OsRng;
    #[test]
    fn authenticated_round_trip_binds_user_enrollment_key_and_version() {
        let key = Key::new("key-1".into(), [7; 32]).unwrap();
        let seed = Seed::from_bytes(b"12345678901234567890").unwrap();
        let mut envelope = key.seal(&seed, "u_alice", "enrollment-1", &OsRng).unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(!encoded.contains("12345678901234567890"));
        let decoded = Envelope::from_json(&encoded).unwrap();
        assert_eq!(
            key.open(&decoded, "u_alice", "enrollment-1")
                .unwrap()
                .bytes(),
            seed.bytes()
        );
        assert!(key.open(&decoded, "u_bob", "enrollment-1").is_err());
        assert!(key.open(&decoded, "u_alice", "enrollment-2").is_err());
        assert!(
            Key::new("key-1".into(), [8; 32])
                .unwrap()
                .open(&decoded, "u_alice", "enrollment-1")
                .is_err()
        );
        assert!(
            Key::new("key-2".into(), [7; 32])
                .unwrap()
                .open(&decoded, "u_alice", "enrollment-1")
                .is_err()
        );
        envelope.ciphertext[0] ^= 1;
        assert!(key.open(&envelope, "u_alice", "enrollment-1").is_err());
        envelope.ciphertext[0] ^= 1;
        envelope.nonce[0] ^= 1;
        assert!(key.open(&envelope, "u_alice", "enrollment-1").is_err());
        envelope.nonce[0] ^= 1;
        envelope.version = 2;
        assert!(key.open(&envelope, "u_alice", "enrollment-1").is_err());
        assert_eq!(format!("{key:?}"), "Key(<redacted>)");
        assert_eq!(format!("{envelope:?}"), "Envelope(<redacted>)");
    }
    #[test]
    fn fresh_nonces_and_bounded_inputs() {
        let key = Key::new("key-1".into(), [7; 32]).unwrap();
        let seed = Seed::from_bytes(&[4; 20]).unwrap();
        let a = key.seal(&seed, "u_a", "e_1", &OsRng).unwrap();
        let b = key.seal(&seed, "u_a", "e_1", &OsRng).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        for value in ["", "bad/key", "a\nb"] {
            assert!(Key::new(value.into(), [0; 32]).is_err());
            assert!(key.seal(&seed, value, "e_1", &OsRng).is_err());
        }
        assert!(Envelope::from_json(&" ".repeat(1025)).is_err());
        assert!(Envelope::from_json("{}").is_err());
    }
}
