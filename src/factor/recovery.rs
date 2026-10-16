//! Recovery codes (ADR-0017 decision 9): `XXXXX-XXXXX-XXXXX` in Crockford
//! base32. The first group is a per-user lookup id (stored plain); the other
//! 50 bits are hashed with Argon2id and compared in constant time by the
//! password-hash verifier. A code is AAL 1 evidence only.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::Rng;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUP: usize = 5;

/// One generated code: the lookup id, the plaintext shown once, and its hash.
pub struct Generated {
    pub lookup: String,
    pub display: Zeroizing<String>,
    pub hash: String,
}

/// A code the user typed, normalized and split.
pub struct Presented {
    pub lookup: String,
    secret: Zeroizing<String>,
}

fn argon2() -> Argon2<'static> {
    // OWASP 2023 Argon2id minimum: 19 MiB, 2 iterations, 1 lane.
    let params = Params::new(19 * 1024, 2, 1, None).expect("static Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn group(rng: &dyn Rng) -> String {
    let mut bytes = [0u8; GROUP];
    rng.fill(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[usize::from(b & 31)] as char)
        .collect()
}

/// Generate `n` codes with distinct lookup ids. CPU-heavy (Argon2id): call
/// from a blocking context.
pub fn generate(rng: &dyn Rng, n: usize) -> Vec<Generated> {
    let mut out: Vec<Generated> = Vec::with_capacity(n);
    while out.len() < n {
        let lookup = group(rng);
        if out.iter().any(|g| g.lookup == lookup) {
            continue;
        }
        let secret = Zeroizing::new(format!("{}{}", group(rng), group(rng)));
        let mut salt = [0u8; 16];
        rng.fill(&mut salt);
        let Ok(salt) = SaltString::encode_b64(&salt) else {
            continue;
        };
        let Ok(hash) = argon2().hash_password(secret.as_bytes(), &salt) else {
            continue;
        };
        let display = Zeroizing::new(format!(
            "{lookup}-{}-{}",
            &secret[..GROUP],
            &secret[GROUP..]
        ));
        out.push(Generated {
            lookup,
            display,
            hash: hash.to_string(),
        });
    }
    out
}

/// Normalize user input: case, spaces and dashes are ignored; Crockford
/// look-alikes (`O`→`0`, `I`/`L`→`1`) are folded. `None` unless exactly 15
/// alphabet characters remain.
pub fn parse(input: &str) -> Option<Presented> {
    if input.len() > 64 {
        return None;
    }
    let mut chars = String::with_capacity(15);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        chars.push(c);
    }
    if chars.len() != 3 * GROUP {
        return None;
    }
    Some(Presented {
        lookup: chars[..GROUP].to_owned(),
        secret: Zeroizing::new(chars[GROUP..].to_owned()),
    })
}

/// Verify a presented code against a stored hash. CPU-heavy: call from a blocking context.
pub fn verify(presented: &Presented, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|h| {
        argon2()
            .verify_password(presented.secret.as_bytes(), &h)
            .is_ok()
    })
}

/// A constant-cost stand-in for an unknown lookup id (no timing signal for
/// which ids exist).
pub fn verify_dummy(presented: &Presented) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let hash = DUMMY.get_or_init(|| {
        let salt = SaltString::encode_b64(&[7u8; 16]).expect("static salt");
        argon2()
            .hash_password(b"0000000000", &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    });
    let _ = verify(presented, hash);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SeededRng;

    #[test]
    fn generated_codes_parse_verify_once_per_hash_and_look_alikes_fold() {
        let rng = SeededRng::new(5);
        let codes = generate(&rng, 3);
        assert_eq!(codes.len(), 3);
        let first = &codes[0];
        assert_eq!(first.display.len(), 17);
        assert!(first.hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        let p = parse(&first.display).unwrap();
        assert_eq!(p.lookup, first.lookup);
        assert!(verify(&p, &first.hash));
        assert!(!verify(&p, &codes[1].hash));
        // Lower case, spaces and look-alikes are accepted.
        let typed = first
            .display
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        assert!(verify(&parse(&typed).unwrap(), &first.hash));
        // One wrong character fails.
        let mut wrong = first.display.to_string();
        let last = wrong.pop().unwrap();
        wrong.push(if last == 'Z' { 'Y' } else { 'Z' });
        assert!(!verify(&parse(&wrong).unwrap(), &first.hash));
        assert!(parse("ABCDE-FGHJK").is_none());
        assert!(parse("ABCDE-FGHJK-MNPQRS").is_none());
        assert!(
            parse("ABCDE-FGHJK-MNPQU").is_none(),
            "U is not in the alphabet"
        );
        assert!(parse(&"A".repeat(100)).is_none());
        assert!(!verify(&p, "not a hash"));
        verify_dummy(&p);
    }
}
