//! Domain-separated projection request hashing. Inputs come from native routing,
//! not an authentication claim; this hash grants no identity or permission.
use sha2::{Digest as _, Sha256};

pub struct Request<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub method: &'a str,
    /// Exact validated origin-form path/query bytes; no URL rewriting here.
    pub target: &'a str,
    /// SHA-256 of the complete transmitted entity. Unknown streaming bodies
    /// require a separate explicit contract, never an empty-body placeholder.
    pub body_sha256: &'a [u8; 32],
}
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidRequest;

pub fn digest(request: &Request<'_>) -> Result<[u8; 32], InvalidRequest> {
    if [request.service, request.audience].iter().any(|value| {
        value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    }) || request.method.is_empty()
        || request.method.len() > 32
        || !request
            .method
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'-')
        || !request.target.starts_with('/')
        || request.target.starts_with("//")
        || request.target.len() > 8192
        || !request
            .target
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
    {
        return Err(InvalidRequest);
    }
    let bytes = request.target.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(InvalidRequest);
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"hangang-zerotrust:credential-projection:request:v1\0");
    for value in [
        request.service.as_bytes(),
        request.audience.as_bytes(),
        request.method.as_bytes(),
        bytes,
        request.body_sha256.as_slice(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bindings_and_field_boundaries_are_distinct() {
        let body = crate::crypto::sha256(b"").0;
        let mut request = Request {
            service: "ab",
            audience: "c",
            method: "GET",
            target: "/private?x=1",
            body_sha256: &body,
        };
        let original = digest(&request).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&original),
            "234488f459d8b3069a74d308d639fa9bfb402b12a9544a413c06c6136a8dab11"
        );
        request.service = "a";
        request.audience = "bc";
        assert_ne!(digest(&request).unwrap(), original);
        request.service = "ab";
        request.audience = "c";
        for target in [
            "/private?x=2",
            "/private/?x=1",
            "/private?x=1&x=1",
            "/%70rivate?x=1",
        ] {
            request.target = target;
            assert_ne!(digest(&request).unwrap(), original);
        }
        request.target = "/private?x=1";
        request.method = "POST";
        assert_ne!(digest(&request).unwrap(), original);
        request.method = "GET";
        let changed = crate::crypto::sha256(b"changed").0;
        request.body_sha256 = &changed;
        assert_ne!(digest(&request).unwrap(), original);
    }
    #[test]
    fn ambiguous_or_malformed_targets_are_refused() {
        let body = [0; 32];
        for target in [
            "",
            "//other.example.test/private",
            "https://other.example.test/",
            "/x#fragment",
            "/x\r\nheader",
            "/x%",
            "/x%0",
            "/x%zz",
            "/x y",
            "/\\other.example.test/private",
        ] {
            assert_eq!(
                digest(&Request {
                    service: "owned",
                    audience: "upstream",
                    method: "GET",
                    target,
                    body_sha256: &body
                }),
                Err(InvalidRequest)
            );
        }
    }
}
