//! Listing cursors: `base64url(key ":" id ":" mac16)`, position only.
//!
//! The MAC is HMAC-SHA-256 over a domain tag and `key:id`, keyed with the
//! process key (a restart invalidates outstanding cursors), cut to 16 bytes.
//! A forged, altered or stale cursor is `invalid_cursor`.

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::store::Cursor;

const DOMAIN_TAG: &[u8] = b"hopae-admin-cursor-v1";
const MAC_LEN: usize = 16;
/// Longest cursor string accepted (a base64 `key:id:mac` of a 64-byte id is well under it).
const MAX_TOKEN: usize = 256;
const MAX_ID: usize = 80;

type HmacSha256 = Hmac<Sha256>;

/// The cursor is not one this process issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCursor;

fn mac(key: &[u8; 32], payload: &[u8]) -> [u8; MAC_LEN] {
    // HMAC accepts keys of any length, so construction cannot fail for a 32-byte key.
    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    m.update(DOMAIN_TAG);
    m.update(&[0]);
    m.update(payload);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The opaque string for `c`.
pub fn encode(key: &[u8; 32], c: &Cursor) -> String {
    let mut bytes = format!("{}:{}", c.key, c.id).into_bytes();
    let tag = mac(key, &bytes);
    bytes.push(b':');
    bytes.extend_from_slice(&tag);
    BASE64URL_NOPAD.encode(&bytes)
}

/// The cursor `token` names, when this process issued it.
pub fn decode(key: &[u8; 32], token: &str) -> Result<Cursor, InvalidCursor> {
    if token.is_empty() || token.len() > MAX_TOKEN {
        return Err(InvalidCursor);
    }
    let bytes = BASE64URL_NOPAD
        .decode(token.as_bytes())
        .map_err(|_| InvalidCursor)?;
    // payload, ':', 16 raw MAC bytes.
    let split = bytes.len().checked_sub(MAC_LEN + 1).ok_or(InvalidCursor)?;
    if bytes[split] != b':' {
        return Err(InvalidCursor);
    }
    let (payload, rest) = bytes.split_at(split);
    let presented = &rest[1..];
    let expected = mac(key, payload);
    if !crate::crypto::ct_eq(&expected, presented) {
        return Err(InvalidCursor);
    }
    let text = std::str::from_utf8(payload).map_err(|_| InvalidCursor)?;
    let (k, id) = text.split_once(':').ok_or(InvalidCursor)?;
    let key_ms: i64 = k.parse().map_err(|_| InvalidCursor)?;
    if !id_ok(id) {
        return Err(InvalidCursor);
    }
    Ok(Cursor {
        key: key_ms,
        id: id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3u8; 32];

    fn cur() -> Cursor {
        Cursor {
            key: 1_800_000_123_456,
            id: "e_01hzabc-DEF_9".into(),
        }
    }

    #[test]
    fn a_cursor_round_trips() {
        let t = encode(&KEY, &cur());
        assert_eq!(decode(&KEY, &t), Ok(cur()));
        let neg = Cursor {
            key: -5,
            id: "u_x".into(),
        };
        assert_eq!(decode(&KEY, &encode(&KEY, &neg)), Ok(neg));
    }

    #[test]
    fn another_key_a_flipped_bit_and_junk_are_refused() {
        let t = encode(&KEY, &cur());
        assert_eq!(decode(&[4u8; 32], &t), Err(InvalidCursor));
        // Flip each character in turn: never accepted as a different cursor.
        for i in 0..t.len() {
            let mut b = t.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            let s = String::from_utf8(b).unwrap();
            if s != t {
                assert_eq!(decode(&KEY, &s), Err(InvalidCursor), "position {i}");
            }
        }
        for junk in ["", "x", "!!!!", &"A".repeat(300), "MTIzOjQ1Ng"] {
            assert_eq!(decode(&KEY, junk), Err(InvalidCursor), "{junk}");
        }
    }
}
