//! Projection receipt crypto primitive. Signature validation is not a permission
//! grant: live state, authority/key selection and atomic replay admission remain required.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
const DOMAIN: &[u8] = b"hangang-zerotrust:projection-receipt:v1\0";
const PAYLOAD: usize = 82;
pub const LENGTH: usize = PAYLOAD + 64;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Authentication = 1,
    Permit = 2,
}
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidReceipt;
pub struct Claims {
    pub purpose: Purpose,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// Native digest must include identity, issuer/key epoch, request/audience,
    /// relevant revisions and the authentication/decision receipt chain.
    pub binding: [u8; 32],
    /// Native CSPRNG nonce. Receivers must consume it atomically, not cache acceptance.
    pub nonce: [u8; 32],
}
/// Authenticated bytes only, not live authorization; cannot be directly constructed.
pub struct VerifiedReceipt(Claims);
impl VerifiedReceipt {
    pub fn claims(&self) -> &Claims {
        &self.0
    }
}
fn valid(claims: &Claims) -> bool {
    claims.issued_ms > 0
        && claims.expires_ms > claims.issued_ms
        && claims.expires_ms - claims.issued_ms <= 1000
        && claims.nonce != [0; 32]
}
fn message(payload: &[u8]) -> Vec<u8> {
    [DOMAIN, payload].concat()
}
pub fn sign(key: &SigningKey, claims: &Claims) -> Result<[u8; LENGTH], InvalidReceipt> {
    if !valid(claims) {
        return Err(InvalidReceipt);
    }
    let mut output = [0; LENGTH];
    output[0] = 1;
    output[1] = claims.purpose as u8;
    output[2..10].copy_from_slice(&claims.issued_ms.to_be_bytes());
    output[10..18].copy_from_slice(&claims.expires_ms.to_be_bytes());
    output[18..50].copy_from_slice(&claims.binding);
    output[50..82].copy_from_slice(&claims.nonce);
    let signature = key.sign(&message(&output[..PAYLOAD]));
    output[PAYLOAD..].copy_from_slice(&signature.to_bytes());
    Ok(output)
}
pub fn verify(
    key: &VerifyingKey,
    bytes: &[u8],
    purpose: Purpose,
    binding: &[u8; 32],
    now_ms: u64,
) -> Result<VerifiedReceipt, InvalidReceipt> {
    if bytes.len() != LENGTH || bytes[0] != 1 || bytes[1] != purpose as u8 || key.is_weak() {
        return Err(InvalidReceipt);
    }
    let signature = Signature::from_slice(&bytes[PAYLOAD..]).map_err(|_| InvalidReceipt)?;
    key.verify_strict(&message(&bytes[..PAYLOAD]), &signature)
        .map_err(|_| InvalidReceipt)?;
    let claims = Claims {
        purpose,
        issued_ms: u64::from_be_bytes(bytes[2..10].try_into().map_err(|_| InvalidReceipt)?),
        expires_ms: u64::from_be_bytes(bytes[10..18].try_into().map_err(|_| InvalidReceipt)?),
        binding: bytes[18..50].try_into().map_err(|_| InvalidReceipt)?,
        nonce: bytes[50..82].try_into().map_err(|_| InvalidReceipt)?,
    };
    if !valid(&claims)
        || now_ms < claims.issued_ms
        || now_ms >= claims.expires_ms
        || !bool::from(claims.binding.ct_eq(binding))
    {
        return Err(InvalidReceipt);
    }
    Ok(VerifiedReceipt(claims))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tamper_purpose_binding_key_and_time_are_fenced() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let claims = Claims {
            purpose: Purpose::Permit,
            issued_ms: 100,
            expires_ms: 1100,
            binding: [9; 32],
            nonce: [8; 32],
        };
        let receipt = sign(&key, &claims).unwrap();
        assert!(
            verify(
                &key.verifying_key(),
                &receipt,
                Purpose::Permit,
                &[9; 32],
                101
            )
            .is_ok()
        );
        for index in 0..LENGTH {
            let mut bad = receipt;
            bad[index] ^= 1;
            assert!(verify(&key.verifying_key(), &bad, Purpose::Permit, &[9; 32], 101).is_err());
        }
        assert!(
            verify(
                &key.verifying_key(),
                &receipt,
                Purpose::Authentication,
                &[9; 32],
                101
            )
            .is_err()
        );
        assert!(
            verify(
                &key.verifying_key(),
                &receipt,
                Purpose::Permit,
                &[0; 32],
                101
            )
            .is_err()
        );
        assert!(
            verify(
                &SigningKey::from_bytes(&[6; 32]).verifying_key(),
                &receipt,
                Purpose::Permit,
                &[9; 32],
                101
            )
            .is_err()
        );
        for now in [0, 99, 1100, u64::MAX] {
            assert!(
                verify(
                    &key.verifying_key(),
                    &receipt,
                    Purpose::Permit,
                    &[9; 32],
                    now
                )
                .is_err()
            );
        }
        for length in [0, 1, LENGTH - 1] {
            assert!(
                verify(
                    &key.verifying_key(),
                    &receipt[..length],
                    Purpose::Permit,
                    &[9; 32],
                    101
                )
                .is_err()
            );
        }
    }
    #[test]
    fn invalid_lifetimes_and_zero_nonce_refuse_signing() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for (issued, expires, nonce) in [
            (0, 1, [1; 32]),
            (100, 100, [1; 32]),
            (100, 1101, [1; 32]),
            (100, 101, [0; 32]),
        ] {
            assert!(
                sign(
                    &key,
                    &Claims {
                        purpose: Purpose::Authentication,
                        issued_ms: issued,
                        expires_ms: expires,
                        binding: [1; 32],
                        nonce
                    }
                )
                .is_err()
            );
        }
    }
}
