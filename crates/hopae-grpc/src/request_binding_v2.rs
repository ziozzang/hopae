//! Pure request-binding v2 codec, not Human authentication or permission evidence.
//! The trusted request owner supplies its actual complete final body and fixed
//! configuration. Destination provenance and actual-header selection are owner
//! responsibilities; hashing this descriptor does not establish either one.
use sha2::{Digest as _, Sha256};

pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_SLOTS: usize = 16;
const MAX_REVISION: u64 = 9_007_199_254_740_991;
const MAX_RESERVED: usize = 64;
const DOMAIN: &[u8] = b"hangang-zerotrust:credential-projection:request:v2\0";
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidRequest;

/// Compiled server configuration metadata, never a proof/capability. Every
/// custom caller, projected credential and identity header must be reserved by
/// its owner. Built-in security/framing names are always forbidden as slots.
#[derive(Debug)]
pub struct HeaderPolicy {
    revision: u64,
    names: Vec<String>,
}
impl HeaderPolicy {
    pub fn new(
        revision: u64,
        names: &[&str],
        reserved_names: &[&str],
    ) -> Result<Self, InvalidRequest> {
        if !(1..=MAX_REVISION).contains(&revision)
            || names.len() > MAX_SLOTS
            || reserved_names.len() > MAX_RESERVED
        {
            return Err(InvalidRequest);
        }
        for (index, name) in reserved_names.iter().enumerate() {
            if !header_name(name) || reserved_names[..index].contains(name) {
                return Err(InvalidRequest);
            }
        }
        if names
            .iter()
            .any(|name| !header_name(name) || forbidden(name) || reserved_names.contains(name))
        {
            return Err(InvalidRequest);
        }
        let mut names = names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(InvalidRequest);
        }
        Ok(Self { revision, names })
    }
}
/// One descriptor for each fixed slot, including an explicit absent value.
/// Unrelated actual request headers do not belong in this bounded slot DTO.
/// Unknown/duplicate/missing descriptors are refused; None differs from Some(b"").
pub struct BoundHeader<'a> {
    pub name: &'a str,
    pub value: Option<&'a [u8]>,
}
pub struct Request<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub route_id: &'a str,
    pub route_revision: u64,
    /// Independently owned selected destination binding; this codec only hashes
    /// it and cannot establish that a caller actually owns the destination.
    pub destination_sha256: &'a [u8; 32],
    pub method: &'a str,
    pub target: &'a str,
    /// Actual complete transformed transmitted bytes, never a caller body digest.
    pub body: &'a [u8],
    pub bound_headers: &'a [BoundHeader<'a>],
}
impl std::fmt::Debug for BoundHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundHeader { [redacted] }")
    }
}
impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestV2 { [redacted] }")
    }
}
fn header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}
fn forbidden(name: &str) -> bool {
    [
        "authorization",
        "proxy-authorization",
        "proxy-authenticate",
        "www-authenticate",
        "cookie",
        "set-cookie",
        "host",
        "forwarded",
        "connection",
        "keep-alive",
        "content-length",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ]
    .contains(&name)
        || [
            "x-forwarded-",
            "x-hopae-",
            "x-hangang-",
            "x-pumgye-",
            "x-sumunjang-",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn valid_request(request: &Request<'_>) -> bool {
    if ![request.service, request.audience, request.route_id]
        .into_iter()
        .all(identifier)
        || !(1..=MAX_REVISION).contains(&request.route_revision)
        || request.destination_sha256.iter().all(|b| *b == 0)
        || request.body.len() > MAX_BODY_BYTES
        || request.method.is_empty()
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
        return false;
    }
    let target = request.target.as_bytes();
    !target.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && (i + 2 >= target.len()
                || !target[i + 1].is_ascii_hexdigit()
                || !target[i + 2].is_ascii_hexdigit())
    })
}
fn framed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}
/// Compute v2 from actual complete body bytes; no raw-body-digest entry point.
/// Binding data is untrusted metadata, not authentication/authorization evidence.
pub fn digest(policy: &HeaderPolicy, request: &Request<'_>) -> Result<[u8; 32], InvalidRequest> {
    if !valid_request(request) || request.bound_headers.len() != policy.names.len() {
        return Err(InvalidRequest);
    }
    let mut seen = 0u16;
    let mut values: [Option<&[u8]>; MAX_SLOTS] = [None; MAX_SLOTS];
    let mut total = 0usize;
    for header in request.bound_headers {
        let index = policy
            .names
            .binary_search_by(|name| name.as_str().cmp(header.name))
            .map_err(|_| InvalidRequest)?;
        let bit = 1u16 << index;
        if seen & bit != 0 {
            return Err(InvalidRequest);
        }
        seen |= bit;
        values[index] = header.value;
        if let Some(value) = header.value {
            if value.len() > 1024 || value.iter().any(|b| *b < 0x20 || *b == 0x7f) {
                return Err(InvalidRequest);
            }
            total += value.len();
            if total > 8192 {
                return Err(InvalidRequest);
            }
        }
    }
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for value in [request.service, request.audience, request.route_id] {
        framed(&mut hash, value.as_bytes());
    }
    hash.update(request.route_revision.to_be_bytes());
    hash.update(request.destination_sha256);
    framed(&mut hash, request.method.as_bytes());
    framed(&mut hash, request.target.as_bytes());
    hash.update((request.body.len() as u64).to_be_bytes());
    hash.update(Sha256::digest(request.body));
    hash.update(policy.revision.to_be_bytes());
    hash.update((policy.names.len() as u16).to_be_bytes());
    // Exact descriptor count plus uniqueness proves every fixed slot is present.
    // None values mean explicitly absent, not an unvalidated missing descriptor.
    for (name, value) in policy.names.iter().zip(values) {
        framed(&mut hash, name.as_bytes());
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            framed(&mut hash, value);
        }
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request<'a>(body: &'a [u8], headers: &'a [BoundHeader<'a>]) -> Request<'a> {
        Request {
            service: "orders",
            audience: "orders-api",
            route_id: "orders-route",
            route_revision: 1,
            destination_sha256: &[1; 32],
            method: "POST",
            target: "/api/orders?x=1&x=2",
            body,
            bound_headers: headers,
        }
    }
    #[test]
    fn actual_body_and_final_route_fields_all_bind() {
        let policy = HeaderPolicy::new(1, &[], &[]).unwrap();
        let mut r = request(b"ab", &[]);
        let original = digest(&policy, &r).unwrap();
        r.body = b"ac";
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.body = b"";
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.body = b"ab";
        r.route_id = "another";
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.route_id = "orders-route";
        r.route_revision = 2;
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.route_revision = 1;
        r.destination_sha256 = &[2; 32];
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.destination_sha256 = &[1; 32];
        r.method = "PUT";
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.method = "POST";
        for target in [
            "/api/orders?x=2&x=1",
            "/orders?x=1&x=2",
            "/api/%6frders?x=1&x=2",
        ] {
            r.target = target;
            assert_ne!(digest(&policy, &r).unwrap(), original);
        }
        r.target = "/api/orders?x=1&x=2";
        r.service = "other";
        assert_ne!(digest(&policy, &r).unwrap(), original);
        r.service = "orders";
        r.audience = "another";
        assert_ne!(digest(&policy, &r).unwrap(), original);
    }
    #[test]
    fn fixed_slots_order_absence_empty_and_exact_values() {
        let p = HeaderPolicy::new(1, &["x-intent", "content-type"], &["x-native-key"]).unwrap();
        let headers = [
            BoundHeader {
                name: "content-type",
                value: Some(b"application/json"),
            },
            BoundHeader {
                name: "x-intent",
                value: None,
            },
        ];
        let before = digest(&p, &request(b"{}", &headers)).unwrap();
        let reverse = [
            BoundHeader {
                name: "x-intent",
                value: None,
            },
            BoundHeader {
                name: "content-type",
                value: Some(b"application/json"),
            },
        ];
        assert_eq!(digest(&p, &request(b"{}", &reverse)).unwrap(), before);
        let empty = [
            BoundHeader {
                name: "content-type",
                value: Some(b"application/json"),
            },
            BoundHeader {
                name: "x-intent",
                value: Some(b""),
            },
        ];
        assert_ne!(digest(&p, &request(b"{}", &empty)).unwrap(), before);
        let exact = [
            BoundHeader {
                name: "content-type",
                value: Some(b" application/json "),
            },
            BoundHeader {
                name: "x-intent",
                value: None,
            },
        ];
        assert_ne!(digest(&p, &request(b"{}", &exact)).unwrap(), before);
        let p2 = HeaderPolicy::new(2, &["content-type", "x-intent"], &[]).unwrap();
        assert_ne!(digest(&p2, &request(b"{}", &headers)).unwrap(), before);
        let unknown = [
            BoundHeader {
                name: "unknown",
                value: None,
            },
            BoundHeader {
                name: "content-type",
                value: None,
            },
        ];
        assert_eq!(digest(&p, &request(b"", &unknown)), Err(InvalidRequest));
        let dup = [
            BoundHeader {
                name: "content-type",
                value: None,
            },
            BoundHeader {
                name: "content-type",
                value: None,
            },
        ];
        assert_eq!(digest(&p, &request(b"", &dup)), Err(InvalidRequest));
        assert_eq!(digest(&p, &request(b"", &[])), Err(InvalidRequest));
    }
    #[test]
    fn policy_bounds_reservations_and_canonical_names_refuse() {
        assert!(HeaderPolicy::new(1, &[], &[]).is_ok());
        for rev in [0, MAX_REVISION + 1] {
            assert!(HeaderPolicy::new(rev, &[], &[]).is_err());
        }
        for name in [
            "Content-Type",
            "x bad",
            "authorization",
            "cookie",
            "content-length",
            "x-hopae-aal",
            "x-forwarded-host",
            "x-hangang-caller",
            ":authority",
            "",
        ] {
            assert!(HeaderPolicy::new(1, &[name], &[]).is_err());
        }
        assert!(HeaderPolicy::new(1, &["x-native-key"], &["x-native-key"]).is_err());
        assert!(HeaderPolicy::new(1, &[], &["X-Key"]).is_err());
        assert!(HeaderPolicy::new(1, &[], &["a", "a"]).is_err());
        assert!(HeaderPolicy::new(1, &["a", "a"], &[]).is_err());
        assert!(HeaderPolicy::new(1, &[], &["a"; 65]).is_err());
        let names = (0..17).map(|n| format!("x-{n}")).collect::<Vec<_>>();
        let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(HeaderPolicy::new(1, &refs, &[]).is_err());
    }
    #[test]
    fn value_and_body_limits_controls_and_redaction() {
        let p = HeaderPolicy::new(1, &["x-intent"], &[]).unwrap();
        for byte in (0..=31).chain([127]) {
            let value = [byte];
            let h = [BoundHeader {
                name: "x-intent",
                value: Some(&value),
            }];
            assert_eq!(digest(&p, &request(b"", &h)), Err(InvalidRequest));
        }
        let h = [BoundHeader {
            name: "x-intent",
            value: Some(&[0x80, 0xff]),
        }];
        assert!(digest(&p, &request(b"", &h)).is_ok());
        let value = vec![b'x'; 1025];
        let h = [BoundHeader {
            name: "x-intent",
            value: Some(&value),
        }];
        assert_eq!(digest(&p, &request(b"", &h)), Err(InvalidRequest));
        let p = HeaderPolicy::new(1, &[], &[]).unwrap();
        let body = vec![0; MAX_BODY_BYTES];
        assert!(digest(&p, &request(&body, &[])).is_ok());
        let body = vec![0; MAX_BODY_BYTES + 1];
        assert_eq!(digest(&p, &request(&body, &[])), Err(InvalidRequest));
        let secret = [BoundHeader {
            name: "reserved-secret",
            value: Some(b"private-token"),
        }];
        let r = request(b"private-body", &secret);
        assert!(!format!("{r:?} {secret:?}").contains("private"));
    }
    #[test]
    fn aggregate_values_and_header_mutation() {
        let names = (0..9).map(|n| format!("x-{n}")).collect::<Vec<_>>();
        let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let value = vec![b'x'; 1024];
        let headers = names
            .iter()
            .map(|name| BoundHeader {
                name,
                value: Some(&value),
            })
            .collect::<Vec<_>>();
        assert!(
            digest(
                &HeaderPolicy::new(1, &refs[..8], &[]).unwrap(),
                &request(b"", &headers[..8])
            )
            .is_ok()
        );
        assert_eq!(
            digest(
                &HeaderPolicy::new(1, &refs, &[]).unwrap(),
                &request(b"", &headers)
            ),
            Err(InvalidRequest)
        );
        let p = HeaderPolicy::new(1, &["x-intent"], &[]).unwrap();
        let a = [BoundHeader {
            name: "x-intent",
            value: Some(b"read"),
        }];
        let b = [BoundHeader {
            name: "x-intent",
            value: Some(b"write"),
        }];
        assert_ne!(
            digest(&p, &request(b"", &a)).unwrap(),
            digest(&p, &request(b"", &b)).unwrap()
        );
        // v1 structurally has no header input; its unchanged golden tests are
        // retained separately. This test claims v2 mutation coverage only.
        let long = "a".repeat(129);
        assert!(HeaderPolicy::new(1, &[&long], &[]).is_err());
        let max = "a".repeat(128);
        assert!(HeaderPolicy::new(1, &[&max], &[]).is_ok());
    }
    #[test]
    fn invalid_scope_target_revisions_and_zero_destination() {
        let p = HeaderPolicy::new(MAX_REVISION, &[], &[]).unwrap();
        let mut r = request(b"", &[]);
        for target in ["", "//other", "/x#f", "/x%", "/x%zz", "/x\\z", "/x y"] {
            r.target = target;
            assert_eq!(digest(&p, &r), Err(InvalidRequest));
        }
        r.target = "/";
        r.route_revision = MAX_REVISION;
        assert!(digest(&p, &r).is_ok());
        for rev in [0, MAX_REVISION + 1] {
            r.route_revision = rev;
            assert_eq!(digest(&p, &r), Err(InvalidRequest));
        }
        r.route_revision = 1;
        r.destination_sha256 = &[0; 32];
        assert_eq!(digest(&p, &r), Err(InvalidRequest));
    }
}

#[cfg(test)]
mod cross_language_vectors {
    use super::*;
    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_python_expected_digests() {
        // Public synthetic fixture, generated by the independent ZT reference
        // encoder; expected SHA values are not derived by this Rust codec.
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/request_binding_v2.json"))
                .unwrap();
        assert_eq!(file["format"], "human-request-binding-v2-reference-1");
        let vectors = file["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 7);
        for vector in vectors {
            let data = &vector["request"];
            let names = vector["manifest"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>();
            let policy = HeaderPolicy::new(
                data["header_policy_revision"].as_u64().unwrap(),
                &names,
                &[],
            )
            .unwrap();
            let body = hex(data["body"].as_str().unwrap());
            let destination: [u8; 32] = hex(data["destination"].as_str().unwrap())
                .try_into()
                .unwrap();
            let slots = vector["slots"].as_array().unwrap();
            let values = slots
                .iter()
                .map(|v| v["value_hex"].as_str().map(hex))
                .collect::<Vec<_>>();
            let headers = slots
                .iter()
                .zip(&values)
                .map(|(v, value)| BoundHeader {
                    name: v["name"].as_str().unwrap(),
                    value: value.as_deref(),
                })
                .collect::<Vec<_>>();
            let request = Request {
                service: data["service"].as_str().unwrap(),
                audience: data["audience"].as_str().unwrap(),
                route_id: data["route_id"].as_str().unwrap(),
                route_revision: data["route_revision"].as_u64().unwrap(),
                destination_sha256: &destination,
                method: data["method"].as_str().unwrap(),
                target: data["target"].as_str().unwrap(),
                body: &body,
                bound_headers: &headers,
            };
            assert_eq!(
                digest(&policy, &request).unwrap().as_slice(),
                hex(vector["sha256"].as_str().unwrap()),
                "{}",
                vector["name"]
            );
        }
    }
}
