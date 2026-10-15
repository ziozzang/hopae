//! Canonical Human owner metadata, not authentication or a lifetime grant.
//! The nonce is the exact issuer process BOOTTIME domain, never a logical name.
const MAX_REVISION: u64 = 9_007_199_254_740_991;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
#[derive(Debug, PartialEq, Eq)]
pub struct Epoch<'a> {
    pub authority: &'a str,
    pub clock_domain: &'a str,
    pub source_scope_revision: u64,
    pub application_generation: u64,
}
fn authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn clock_domain(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn revision(value: &str) -> Result<u64, Refused> {
    if value.is_empty()
        || value.len() > 16
        || value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Refused);
    }
    let value = value.parse::<u64>().map_err(|_| Refused)?;
    (1..=MAX_REVISION)
        .contains(&value)
        .then_some(value)
        .ok_or(Refused)
}
pub fn encode(
    authority_ref: &str,
    source: u64,
    application: u64,
    nonce: &str,
) -> Result<String, Refused> {
    if !authority(authority_ref)
        || !clock_domain(nonce)
        || !(1..=MAX_REVISION).contains(&source)
        || !(1..=MAX_REVISION).contains(&application)
    {
        return Err(Refused);
    }
    let value = format!("hobs1:{nonce}:{authority_ref}:s:{source}:a:{application}");
    if value.len() > 128 {
        return Err(Refused);
    }
    Ok(value)
}
pub fn decode(value: &str) -> Result<Epoch<'_>, Refused> {
    if value.len() > 128 {
        return Err(Refused);
    }
    let (nonce, rest) = value
        .strip_prefix("hobs1:")
        .ok_or(Refused)?
        .split_once(':')
        .ok_or(Refused)?;
    let (prefix, application) = rest.rsplit_once(":a:").ok_or(Refused)?;
    let (base, source) = prefix.rsplit_once(":s:").ok_or(Refused)?;
    let source = revision(source)?;
    let application = revision(application)?;
    if encode(base, source, application, nonce)?.as_bytes() != value.as_bytes() {
        return Err(Refused);
    }
    Ok(Epoch {
        authority: base,
        clock_domain: nonce,
        source_scope_revision: source,
        application_generation: application,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const NONCE: &str = "11112222333344445555666677778888";
    #[test]
    fn canonical_golden_and_borrowed_process_domain() {
        let expected = "hobs1:11112222333344445555666677778888:example-hopae:s:7:a:11";
        assert_eq!(encode("example-hopae", 7, 11, NONCE).unwrap(), expected);
        assert_eq!(
            decode(expected).unwrap(),
            Epoch {
                authority: "example-hopae",
                clock_domain: NONCE,
                source_scope_revision: 7,
                application_generation: 11
            }
        );
        assert_ne!(
            encode("example-hopae", 7, 11, NONCE).unwrap(),
            encode("example-hopae", 7, 11, "21112222333344445555666677778888").unwrap()
        );
    }
    #[test]
    fn delimiter_authorities_are_unambiguous_and_bounds_are_exact() {
        for base in [
            "a:s:1",
            "a:a:2",
            "a:s:1:a:2",
            ":leading",
            "trailing:",
            "x:service:1:app:2",
        ] {
            let value = encode(base, MAX_REVISION, MAX_REVISION, NONCE).unwrap();
            let parsed = decode(&value).unwrap();
            assert!(crate::service_epoch::decode(&value).is_err());
            assert!(crate::service_epoch::decode_clock(&value).is_err());
            let legacy = crate::service_epoch::encode(base, 7, 11).unwrap();
            assert!(decode(&legacy).is_err());
            assert_eq!(parsed.authority, base);
            assert_eq!(
                (parsed.source_scope_revision, parsed.application_generation),
                (MAX_REVISION, MAX_REVISION)
            );
        }
        let base = "a".repeat(40);
        let value = encode(&base, MAX_REVISION, MAX_REVISION, NONCE).unwrap();
        assert_eq!(value.len(), 117);
        assert_eq!(decode(&value).unwrap().authority, base);
        assert!(encode(&"a".repeat(41), 1, 1, NONCE).is_err());
        for invalid in ["", "a/b", "a b", "é", "a\n"] {
            assert!(encode(invalid, 1, 1, NONCE).is_err());
        }
    }
    #[test]
    fn noncanonical_numbers_nonce_prefix_and_class_are_refused() {
        let good = encode("owner", 7, 11, NONCE).unwrap();
        for bad in [
            good.replace("hobs1:", "WOBS1:"),
            good.replace(":s:7:", ":s:07:"),
            good.replace(":a:11", ":a:011"),
            good.replace(":s:7:", ":s:+7:"),
            good.replace(":a:11", ":a:0"),
            good.replace(":a:11", ":a:9007199254740992"),
            good.replace(":s:7:", ":s:7.0:"),
            format!("{good}:a:1"),
            good.replace(NONCE, "00000000000000000000000000000000"),
            good.replace(NONCE, "ABCDEF12345678901234567890123456"),
            good.replace(NONCE, "1111222233334444555566667777888"),
            format!("{good} "),
            "x".repeat(129),
        ] {
            assert!(decode(&bad).is_err(), "accepted {bad:?}");
        }
        for invalid in [0, MAX_REVISION + 1, u64::MAX] {
            assert!(encode("owner", invalid, 1, NONCE).is_err());
            assert!(encode("owner", 1, invalid, NONCE).is_err());
        }
        let service = crate::service_epoch::encode_clock("owner", 7, 11, NONCE).unwrap();
        assert!(decode(&service).is_err());
        assert!(crate::service_epoch::decode_clock(&good).is_err());
    }
}
