//! The signed membership projection (Hangang ADR 0021): a paged snapshot and
//! an incremental change feed of person → GroupRef memberships, restricted
//! to the group vocabulary the consumer names, each page signed with the
//! `groups.projection` Ed25519 key.
//!
//! Envelope (JSON):
//!
//! ```text
//! {"format":"hopae.membership-projection.v1",
//!  "key":{"issuer_ref":"…","key_epoch":1},
//!  "payload":"<base64url, no padding: the exact payload bytes>",
//!  "signature":"<base64url, no padding: Ed25519 over DOMAIN || payload bytes>"}
//! ```
//!
//! The signature covers the exact payload bytes, so a verifier never
//! canonicalizes JSON: it verifies, then parses. [`verify`] is the reference
//! verifier of the contract documented in `docs/GROUPS.md`.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::config::ProjectionKey;

/// Domain separation of the projection signature: distinct from every other
/// Hopae signature (receipts use `hangang-zerotrust:projection-receipt:v1`).
pub const DOMAIN: &[u8] = b"hangang-zerotrust:hopae-membership-projection:v1\0";
/// The envelope `format`.
pub const FORMAT: &str = "hopae.membership-projection.v1";
/// Largest payload a verifier accepts (and Hopae produces).
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// The highest assurance level Hopae issues today (the ADR 0021 capability
/// advertisement carried in every page).
pub const MAX_AAL: u8 = 2;

/// A base64 (standard) Ed25519 public key, when well formed and not weak.
pub fn public_key(b64: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = STANDARD.decode(b64).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    (!key.is_weak()).then_some(key)
}

/// The loaded signing key.
pub struct ProjectionSigner {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub audience: String,
    key: SigningKey,
}

impl std::fmt::Debug for ProjectionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionSigner")
            .field("issuer_ref", &self.issuer_ref)
            .field("key_epoch", &self.key_epoch)
            .finish_non_exhaustive()
    }
}

/// Why a projection key could not be loaded (never carries key material).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("groups.projection.public_key is invalid")]
    PublicKey,
    #[error("groups.projection.seed_env is unset or not a base64 32-byte seed")]
    Seed,
    #[error("groups.projection seed does not match public_key")]
    Mismatch,
    #[error("groups.projection must not reuse the receipt issuer key")]
    Reused,
}

impl ProjectionSigner {
    /// Load the seed from the environment reference and check it against
    /// the configured public key. `receipt_key` is the receipt issuer's
    /// public key, which this purpose must not share.
    pub fn load(
        cfg: &ProjectionKey,
        env: &dyn Fn(&str) -> Option<String>,
        receipt_key: Option<&str>,
    ) -> Result<ProjectionSigner, KeyError> {
        let public = public_key(&cfg.public_key).ok_or(KeyError::PublicKey)?;
        if receipt_key.is_some_and(|r| public_key(r) == Some(public)) {
            return Err(KeyError::Reused);
        }
        let value = Zeroizing::new(env(&cfg.seed_env).ok_or(KeyError::Seed)?);
        let bytes = Zeroizing::new(
            STANDARD
                .decode(value.trim().as_bytes())
                .map_err(|_| KeyError::Seed)?,
        );
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(bytes.as_slice().try_into().map_err(|_| KeyError::Seed)?);
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key() != public {
            return Err(KeyError::Mismatch);
        }
        Ok(ProjectionSigner {
            issuer_ref: cfg.issuer_ref.clone(),
            key_epoch: cfg.key_epoch,
            audience: cfg.audience.clone(),
            key,
        })
    }

    #[cfg(test)]
    pub fn from_seed(seed: [u8; 32], issuer_ref: &str, epoch: u64, audience: &str) -> Self {
        ProjectionSigner {
            issuer_ref: issuer_ref.into(),
            key_epoch: epoch,
            audience: audience.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.key.verifying_key().to_bytes())
    }

    /// Sign `payload` (serialized once; those exact bytes are signed).
    pub fn seal<T: Serialize>(&self, payload: &T) -> Result<Envelope, serde_json::Error> {
        let bytes = serde_json::to_vec(payload)?;
        let mut message = Vec::with_capacity(DOMAIN.len() + bytes.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&bytes);
        let signature = self.key.sign(&message);
        Ok(Envelope {
            format: FORMAT.into(),
            key: KeyId {
                issuer_ref: self.issuer_ref.clone(),
                key_epoch: self.key_epoch,
            },
            payload: URL_SAFE_NO_PAD.encode(&bytes),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyId {
    pub issuer_ref: String,
    pub key_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub key: KeyId,
    pub payload: String,
    pub signature: String,
}

/// The fields every page carries (the payload is one JSON object).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// `snapshot` or `changes`.
    pub kind: String,
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub audience: String,
    /// The store identity (its Human realm): a different value means a
    /// different or restored store; the consumer takes a new snapshot.
    pub store: String,
    /// SHA-256 (hex) of the sorted, de-duplicated vocabulary joined by `\n`.
    pub vocabulary_sha256: String,
    /// Milliseconds since the epoch at signing.
    pub issued_at: i64,
    /// ADR 0021 capability advertisement: the highest AAL Hopae issues.
    pub max_aal: u8,
}

/// Why a page was not accepted by [`verify`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed envelope")]
    Malformed,
    #[error("unknown key")]
    UnknownKey,
    #[error("bad signature")]
    Signature,
    #[error("payload does not match the expected binding")]
    Binding,
}

/// The digest a page binds its vocabulary with.
pub fn vocabulary_digest(groups: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut v: Vec<&str> = groups.iter().map(String::as_str).collect();
    v.sort_unstable();
    v.dedup();
    data_encoding::HEXLOWER.encode(&Sha256::digest(v.join("\n").as_bytes()))
}

/// Reference verifier (the contract Pumgye implements): the envelope format,
/// a pinned key for `(issuer_ref, key_epoch)` from `keys`, the signature over
/// `DOMAIN || payload` with strict Ed25519 verification, then the header
/// binding: `kind` is the one asked for, `issuer_ref`/`key_epoch` equal the envelope's, the audience and
/// vocabulary digest equal the expected ones, and `issued_at` is within
/// `max_age_ms` of `now_ms` (and not more than 60 s ahead). Returns the
/// parsed payload.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    envelope: &str,
    keys: &dyn Fn(&str, u64) -> Option<VerifyingKey>,
    kind: &str,
    audience: &str,
    vocabulary_sha256: &str,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<serde_json::Value, VerifyError> {
    if envelope.len() > MAX_PAYLOAD_BYTES * 2 {
        return Err(VerifyError::Malformed);
    }
    let env: Envelope = serde_json::from_str(envelope).map_err(|_| VerifyError::Malformed)?;
    if env.format != FORMAT {
        return Err(VerifyError::Malformed);
    }
    let key = keys(&env.key.issuer_ref, env.key.key_epoch).ok_or(VerifyError::UnknownKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(env.payload.as_bytes())
        .map_err(|_| VerifyError::Malformed)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(VerifyError::Malformed);
    }
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(env.signature.as_bytes())
        .map_err(|_| VerifyError::Malformed)?
        .try_into()
        .map_err(|_| VerifyError::Malformed)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + bytes.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&bytes);
    key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| VerifyError::Signature)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| VerifyError::Malformed)?;
    let header: Header =
        serde_json::from_value(value.clone()).map_err(|_| VerifyError::Malformed)?;
    if header.kind != kind
        || header.issuer_ref != env.key.issuer_ref
        || header.key_epoch != env.key.key_epoch
        || header.audience != audience
        || header.vocabulary_sha256 != vocabulary_sha256
        || header.issued_at > now_ms + 60_000
        || now_ms - header.issued_at > max_age_ms
    {
        return Err(VerifyError::Binding);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signer() -> ProjectionSigner {
        ProjectionSigner::from_seed([9; 32], "hopae-groups", 3, "pumgye")
    }

    fn page(s: &ProjectionSigner, at: i64, vocab: &str) -> serde_json::Value {
        json!({
            "kind": "snapshot", "issuer_ref": s.issuer_ref, "key_epoch": s.key_epoch,
            "audience": "pumgye", "store": "realm", "vocabulary_sha256": vocab,
            "issued_at": at, "max_aal": 2, "entries": []
        })
    }

    #[test]
    fn a_sealed_page_verifies_and_any_change_is_refused() {
        let s = signer();
        let vk = s.key.verifying_key();
        let keys = |i: &str, e: u64| (i == "hopae-groups" && e == 3).then_some(vk);
        let vocab = vocabulary_digest(&["grp1:B".into(), "grp1:A".into(), "grp1:A".into()]);
        assert_eq!(
            vocab,
            vocabulary_digest(&["grp1:A".into(), "grp1:B".into()])
        );
        let env = s.seal(&page(&s, 1_000, &vocab)).unwrap();
        let text = serde_json::to_string(&env).unwrap();
        let v = verify(&text, &keys, "snapshot", "pumgye", &vocab, 2_000, 60_000).unwrap();
        assert_eq!(v["kind"], "snapshot");
        // A snapshot page is not a changes page.
        assert_eq!(
            verify(&text, &keys, "changes", "pumgye", &vocab, 2_000, 60_000),
            Err(VerifyError::Binding)
        );

        // Tampered payload, signature, key id, audience, vocabulary, age.
        let mut bad = env.clone();
        let mut longer = serde_json::to_vec(&page(&s, 1_000, &vocab)).unwrap();
        longer.push(b' ');
        bad.payload = URL_SAFE_NO_PAD.encode(&longer);
        assert_eq!(
            verify(
                &serde_json::to_string(&bad).unwrap(),
                &keys,
                "snapshot",
                "pumgye",
                &vocab,
                2_000,
                60_000
            ),
            Err(VerifyError::Signature)
        );
        let mut bad = env.clone();
        bad.key.key_epoch = 4;
        assert_eq!(
            verify(
                &serde_json::to_string(&bad).unwrap(),
                &keys,
                "snapshot",
                "pumgye",
                &vocab,
                2_000,
                60_000
            ),
            Err(VerifyError::UnknownKey)
        );
        assert_eq!(
            verify(&text, &keys, "snapshot", "other", &vocab, 2_000, 60_000),
            Err(VerifyError::Binding)
        );
        assert_eq!(
            verify(&text, &keys, "snapshot", "pumgye", "00", 2_000, 60_000),
            Err(VerifyError::Binding)
        );
        assert_eq!(
            verify(&text, &keys, "snapshot", "pumgye", &vocab, 100_000, 60_000),
            Err(VerifyError::Binding)
        );
        // A signature by another key under the pinned id.
        let other = ProjectionSigner::from_seed([8; 32], "hopae-groups", 3, "pumgye");
        let forged = other.seal(&page(&other, 1_000, &vocab)).unwrap();
        assert_eq!(
            verify(
                &serde_json::to_string(&forged).unwrap(),
                &keys,
                "snapshot",
                "pumgye",
                &vocab,
                2_000,
                60_000
            ),
            Err(VerifyError::Signature)
        );
        // A receipt-domain signature over the same bytes is not a projection.
        let bytes = URL_SAFE_NO_PAD.decode(env.payload.as_bytes()).unwrap();
        let mut m = b"hangang-zerotrust:projection-receipt:v1\0".to_vec();
        m.extend_from_slice(&bytes);
        let mut cross = env.clone();
        cross.signature = URL_SAFE_NO_PAD.encode(s.key.sign(&m).to_bytes());
        assert_eq!(
            verify(
                &serde_json::to_string(&cross).unwrap(),
                &keys,
                "snapshot",
                "pumgye",
                &vocab,
                2_000,
                60_000
            ),
            Err(VerifyError::Signature)
        );
    }

    #[test]
    fn keys_load_from_the_environment_and_refuse_mismatch_and_reuse() {
        let s = signer();
        let cfg = ProjectionKey {
            issuer_ref: "hopae-groups".into(),
            key_epoch: 3,
            public_key: s.public_key_b64(),
            seed_env: "SEED".into(),
            audience: "pumgye".into(),
        };
        let good = |_: &str| Some(STANDARD.encode([9u8; 32]));
        assert!(ProjectionSigner::load(&cfg, &good, None).is_ok());
        assert_eq!(
            ProjectionSigner::load(&cfg, &|_| None, None).unwrap_err(),
            KeyError::Seed
        );
        assert_eq!(
            ProjectionSigner::load(&cfg, &|_| Some(STANDARD.encode([1u8; 32])), None).unwrap_err(),
            KeyError::Mismatch
        );
        assert_eq!(
            ProjectionSigner::load(&cfg, &good, Some(&cfg.public_key)).unwrap_err(),
            KeyError::Reused
        );
        assert!(
            format!("{:?}", ProjectionSigner::load(&cfg, &good, None).unwrap())
                .contains("hopae-groups")
        );
    }
}
