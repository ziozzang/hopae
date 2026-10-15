//! Private validation of untrusted Human wire metadata, never authentication.
//! The fixed authenticated PEP owns actual final bytes. Native Engine/Current
//! and issuer owners must independently authenticate before this data is signed.
use hopae_grpc::{request_binding_v2, v1};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const SAFE: u64 = 9_007_199_254_740_991;
const DOMAIN: &[u8] = b"hangang-zerotrust:credential-projection:request:v2\0";
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;

/// Native startup/configuration data. Never populated from the incoming DTO.
pub(crate) struct Configuration<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub application: &'a str,
    pub route: &'a str,
    pub route_revision: u64,
    pub destination: [u8; 32],
    pub header_revision: u64,
    pub headers: &'a [&'a str],
    pub reserved_headers: &'a [&'a str],
    pub maximum_entity_bytes: u64,
}
/// Immutable compiled metadata, not a source or authorization capability.
pub(crate) struct Scope {
    service: String,
    audience: String,
    application: String,
    route: String,
    route_revision: u64,
    destination: [u8; 32],
    header_revision: u64,
    headers: Vec<String>,
    maximum_entity_bytes: u64,
}
/// No raw body, cookies, application header values or target are retained here.
/// This value proves data validation only; an actual native Checked is separate.
pub(crate) struct Binding {
    scope: Arc<Scope>,
    method: String,
    sha256: [u8; 32],
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn target(value: &str) -> bool {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.len() > 8192
        || !value
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
    {
        return false;
    }
    let bytes = value.as_bytes();
    !bytes.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
    })
}
fn framed(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}
#[allow(dead_code)] // Wired to the additive Human issuer in the next integration.
impl Scope {
    pub(crate) fn compile(c: Configuration<'_>) -> Result<Arc<Self>, Refused> {
        if ![c.service, c.audience, c.application, c.route]
            .into_iter()
            .all(identifier)
            || !(1..=SAFE).contains(&c.route_revision)
            || c.destination.iter().all(|b| *b == 0)
            || c.maximum_entity_bytes > request_binding_v2::MAX_BODY_BYTES as u64
        {
            return Err(Refused);
        }
        // Reuse the actual H1 policy validator, including custom credential and
        // identity reservations; no prehashed-body API is added to that SDK.
        request_binding_v2::HeaderPolicy::new(c.header_revision, c.headers, c.reserved_headers)
            .map_err(|_| Refused)?;
        let mut headers = c
            .headers
            .iter()
            .map(|h| (*h).to_owned())
            .collect::<Vec<_>>();
        headers.sort_unstable();
        Ok(Arc::new(Self {
            service: c.service.into(),
            audience: c.audience.into(),
            application: c.application.into(),
            route: c.route.into(),
            route_revision: c.route_revision,
            destination: c.destination,
            header_revision: c.header_revision,
            headers,
            maximum_entity_bytes: c.maximum_entity_bytes,
        }))
    }
    pub(crate) fn validate(
        self: &Arc<Self>,
        service: &str,
        audience: &str,
        input: &v1::HumanFinalRequest,
    ) -> Result<Binding, Refused> {
        if service != self.service
            || audience != self.audience
            || input.binding_contract != 2
            || input.route_id != self.route
            || input.route_revision != self.route_revision
            || input.destination_sha256.as_slice() != self.destination
            || input.header_policy_revision != self.header_revision
            || input.entity_length > self.maximum_entity_bytes
            || input.entity_sha256.len() != 32
            || input.entity_sha256.iter().all(|b| *b == 0)
            || input.method.is_empty()
            || input.method.len() > 32
            || !input
                .method
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'-')
            || !target(&input.target)
            || input.headers.len() != self.headers.len()
        {
            return Err(Refused);
        }
        if input.entity_length == 0 && input.entity_sha256.as_slice() != &Sha256::digest(b"")[..] {
            return Err(Refused);
        }
        let mut seen = 0u16;
        let mut values: [Option<&[u8]>; 16] = [None; 16];
        let mut total = 0usize;
        for h in &input.headers {
            let index = self.headers.binary_search(&h.name).map_err(|_| Refused)?;
            let bit = 1u16 << index;
            if seen & bit != 0
                || (!h.present && !h.value.is_empty())
                || h.value.len() > 1024
                || h.value.iter().any(|b| *b < 32 || *b == 127)
            {
                return Err(Refused);
            }
            seen |= bit;
            total += h.value.len();
            if total > 8192 {
                return Err(Refused);
            }
            values[index] = h.present.then_some(h.value.as_slice());
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        for v in [&self.service, &self.audience, &self.route] {
            framed(&mut hash, v.as_bytes());
        }
        hash.update(self.route_revision.to_be_bytes());
        hash.update(self.destination);
        framed(&mut hash, input.method.as_bytes());
        framed(&mut hash, input.target.as_bytes());
        hash.update(input.entity_length.to_be_bytes());
        hash.update(&input.entity_sha256);
        hash.update(self.header_revision.to_be_bytes());
        hash.update((self.headers.len() as u16).to_be_bytes());
        for (name, value) in self.headers.iter().zip(values) {
            framed(&mut hash, name.as_bytes());
            hash.update([u8::from(value.is_some())]);
            if let Some(value) = value {
                framed(&mut hash, value);
            }
        }
        Ok(Binding {
            scope: self.clone(),
            method: input.method.clone(),
            sha256: hash.finalize().into(),
        })
    }
}
#[allow(dead_code)]
impl Binding {
    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub(crate) fn method(&self) -> &str {
        &self.method
    }
    pub(crate) fn application(&self) -> &str {
        &self.scope.application
    }
    pub(crate) fn route(&self) -> &str {
        &self.scope.route
    }
    pub(crate) fn service(&self) -> &str {
        &self.scope.service
    }
    pub(crate) fn audience(&self) -> &str {
        &self.scope.audience
    }
    pub(crate) fn belongs_to(&self, scope: &Arc<Scope>) -> bool {
        Arc::ptr_eq(&self.scope, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn configuration<'a>(headers: &'a [&'a str], reserved: &'a [&'a str]) -> Configuration<'a> {
        Configuration {
            service: "orders",
            audience: "orders-api",
            application: "orders-app",
            route: "orders-route",
            route_revision: 7,
            destination: [1; 32],
            header_revision: 11,
            headers,
            reserved_headers: reserved,
            maximum_entity_bytes: request_binding_v2::MAX_BODY_BYTES as u64,
        }
    }
    fn configured(headers: &[&str], reserved: &[&str]) -> Result<Arc<Scope>, Refused> {
        Scope::compile(configuration(headers, reserved))
    }
    fn descriptor() -> v1::HumanFinalRequest {
        v1::HumanFinalRequest {
            binding_contract: 2,
            method: "POST".into(),
            target: "/upstream/orders?x=1&x=2".into(),
            entity_sha256: Sha256::digest(b"body").to_vec(),
            entity_length: 4,
            route_id: "orders-route".into(),
            route_revision: 7,
            destination_sha256: vec![1; 32],
            header_policy_revision: 11,
            headers: vec![v1::HumanBoundHeader {
                name: "x-order-intent".into(),
                present: true,
                value: b"create".to_vec(),
            }],
        }
    }
    #[test]
    fn metadata_hash_matches_actual_body_codec_and_all_independent_vectors() {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../crates/hopae-grpc/tests/fixtures/request_binding_v2.json"
        ))
        .unwrap();
        let vectors = file["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 7);
        for vector in vectors {
            let d = &vector["request"];
            let names = vector["manifest"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>();
            let body = hex(d["body"].as_str().unwrap());
            let destination: [u8; 32] = hex(d["destination"].as_str().unwrap()).try_into().unwrap();
            let scope = Scope::compile(Configuration {
                service: d["service"].as_str().unwrap(),
                audience: d["audience"].as_str().unwrap(),
                application: "example-app",
                route: d["route_id"].as_str().unwrap(),
                route_revision: d["route_revision"].as_u64().unwrap(),
                destination,
                header_revision: d["header_policy_revision"].as_u64().unwrap(),
                headers: &names,
                reserved_headers: &[],
                maximum_entity_bytes: request_binding_v2::MAX_BODY_BYTES as u64,
            })
            .unwrap();
            let headers = vector["slots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|slot| v1::HumanBoundHeader {
                    name: slot["name"].as_str().unwrap().into(),
                    present: slot["value_hex"].is_string(),
                    value: slot["value_hex"].as_str().map(hex).unwrap_or_default(),
                })
                .collect::<Vec<_>>();
            let dto = v1::HumanFinalRequest {
                binding_contract: 2,
                method: d["method"].as_str().unwrap().into(),
                target: d["target"].as_str().unwrap().into(),
                entity_sha256: Sha256::digest(&body).to_vec(),
                entity_length: body.len() as u64,
                route_id: scope.route.clone(),
                route_revision: scope.route_revision,
                destination_sha256: destination.to_vec(),
                header_policy_revision: scope.header_revision,
                headers,
            };
            let bound = scope
                .validate(&scope.service, &scope.audience, &dto)
                .unwrap();
            assert_eq!(
                bound.sha256().as_slice(),
                hex(vector["sha256"].as_str().unwrap())
            );
            let actual_headers = dto
                .headers
                .iter()
                .map(|h| request_binding_v2::BoundHeader {
                    name: &h.name,
                    value: h.present.then_some(h.value.as_slice()),
                })
                .collect::<Vec<_>>();
            let policy =
                request_binding_v2::HeaderPolicy::new(scope.header_revision, &names, &[]).unwrap();
            let actual = request_binding_v2::digest(
                &policy,
                &request_binding_v2::Request {
                    service: &scope.service,
                    audience: &scope.audience,
                    route_id: &scope.route,
                    route_revision: scope.route_revision,
                    destination_sha256: &destination,
                    method: &dto.method,
                    target: &dto.target,
                    body: &body,
                    bound_headers: &actual_headers,
                },
            )
            .unwrap();
            assert_eq!(bound.sha256(), actual);
        }
    }
    #[test]
    fn fixed_owners_cannot_be_selected_by_incoming_descriptor() {
        let scope = configured(&["x-order-intent"], &["x-backend-key"]).unwrap();
        let base = descriptor();
        let bound = scope.validate("orders", "orders-api", &base).unwrap();
        assert!(bound.belongs_to(&scope));
        assert!(!bound.belongs_to(&configured(&["x-order-intent"], &["x-backend-key"]).unwrap()));
        assert_eq!(bound.application(), "orders-app");
        assert_eq!(bound.route(), "orders-route");
        assert_eq!(bound.method(), "POST");
        assert_eq!(bound.service(), "orders");
        assert_eq!(bound.audience(), "orders-api");
        assert!(scope.validate("wrong", "orders-api", &base).is_err());
        assert!(scope.validate("orders", "wrong", &base).is_err());
        for change in 0..5 {
            let mut input = base.clone();
            match change {
                0 => input.binding_contract = 1,
                1 => input.route_id = "other".into(),
                2 => input.route_revision += 1,
                3 => input.destination_sha256[0] ^= 1,
                _ => input.header_policy_revision += 1,
            }
            assert!(scope.validate("orders", "orders-api", &input).is_err());
        }
        assert!(configured(&["x-backend-key"], &["x-backend-key"]).is_err());
        assert!(configured(&["cookie"], &[]).is_err());
    }
    #[test]
    fn malformed_metadata_and_ambiguous_headers_refuse_without_body_substitution() {
        let scope = configured(&["x-order-intent"], &[]).unwrap();
        let base = descriptor();
        for change in 0..11 {
            let mut input = base.clone();
            match change {
                0 => input.entity_sha256.clear(),
                1 => input.entity_sha256.fill(0),
                2 => input.entity_length = request_binding_v2::MAX_BODY_BYTES as u64 + 1,
                3 => input.entity_length = 0,
                4 => input.headers[0].present = false,
                5 => input.headers.push(input.headers[0].clone()),
                6 => input.headers.clear(),
                7 => input.headers[0].name = "x-other".into(),
                8 => input.target = "/x%zz".into(),
                9 => input.method = "post".into(),
                _ => input.headers[0].value = vec![b'x'; 1025],
            }
            assert!(
                scope.validate("orders", "orders-api", &input).is_err(),
                "{change}"
            );
        }
        for control in (0..32).chain(std::iter::once(127)) {
            let mut input = base.clone();
            input.headers[0].value = vec![control];
            assert!(scope.validate("orders", "orders-api", &input).is_err());
        }
        let mut empty = base.clone();
        empty.entity_length = 0;
        empty.entity_sha256 = Sha256::digest(b"").to_vec();
        assert!(scope.validate("orders", "orders-api", &empty).is_ok());
        let original = scope
            .validate("orders", "orders-api", &base)
            .unwrap()
            .sha256();
        for change in 0..4 {
            let mut input = base.clone();
            match change {
                0 => input.entity_length += 1,
                1 => input.entity_sha256[0] ^= 1,
                2 => input.target.push_str("&x=3"),
                _ => input.headers[0].value = vec![0x80, 0xff],
            }
            assert_ne!(
                scope
                    .validate("orders", "orders-api", &input)
                    .unwrap()
                    .sha256(),
                original
            );
        }
    }

    #[test]
    fn sixteen_slots_aggregate_boundaries_order_and_presence_are_exact() {
        let owned = (0..17).map(|i| format!("x-intent-{i}")).collect::<Vec<_>>();
        let names = owned.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(configured(&names, &[]).is_err());
        let scope = configured(&names[..16], &[]).unwrap();
        let mut input = descriptor();
        input.headers = names[..16]
            .iter()
            .map(|name| v1::HumanBoundHeader {
                name: (*name).into(),
                present: true,
                value: vec![b'x'; 512],
            })
            .collect();
        let exact = scope
            .validate("orders", "orders-api", &input)
            .unwrap()
            .sha256();
        input.headers.reverse();
        assert_eq!(
            scope
                .validate("orders", "orders-api", &input)
                .unwrap()
                .sha256(),
            exact
        );
        input.headers[0].value.push(b'x'); // 8193 total, each value still valid.
        assert!(scope.validate("orders", "orders-api", &input).is_err());
        input.headers[0].value.pop();
        input.headers.push(v1::HumanBoundHeader {
            name: names[16].into(),
            present: false,
            value: vec![],
        });
        assert!(scope.validate("orders", "orders-api", &input).is_err());
        input.headers.pop();
        input.headers[0].value.clear();
        let present_empty = scope
            .validate("orders", "orders-api", &input)
            .unwrap()
            .sha256();
        input.headers[0].present = false;
        assert_ne!(
            scope
                .validate("orders", "orders-api", &input)
                .unwrap()
                .sha256(),
            present_empty
        );
        input.headers[1] = input.headers[0].clone(); // Same count, duplicate slot.
        assert!(scope.validate("orders", "orders-api", &input).is_err());
    }

    #[test]
    fn actual_maximum_body_and_configured_lower_limits_match_sdk() {
        let scope = configured(&[], &[]).unwrap();
        let body = vec![b'x'; request_binding_v2::MAX_BODY_BYTES];
        let mut input = descriptor();
        input.headers.clear();
        input.entity_length = body.len() as u64;
        input.entity_sha256 = Sha256::digest(&body).to_vec();
        let binding = scope.validate("orders", "orders-api", &input).unwrap();
        let policy = request_binding_v2::HeaderPolicy::new(11, &[], &[]).unwrap();
        assert_eq!(
            binding.sha256(),
            request_binding_v2::digest(
                &policy,
                &request_binding_v2::Request {
                    service: "orders",
                    audience: "orders-api",
                    route_id: "orders-route",
                    route_revision: 7,
                    destination_sha256: &[1; 32],
                    method: &input.method,
                    target: &input.target,
                    body: &body,
                    bound_headers: &[],
                }
            )
            .unwrap()
        );
        input.entity_length += 1;
        assert!(scope.validate("orders", "orders-api", &input).is_err());
        let mut config = configuration(&[], &[]);
        config.maximum_entity_bytes = 4;
        let lower = Scope::compile(config).unwrap();
        input.entity_length = 4;
        input.entity_sha256 = Sha256::digest(b"body").to_vec();
        assert!(lower.validate("orders", "orders-api", &input).is_ok());
        input.entity_length = 5;
        assert!(lower.validate("orders", "orders-api", &input).is_err());
        let mut config = configuration(&[], &[]);
        config.maximum_entity_bytes = 0;
        let empty_only = Scope::compile(config).unwrap();
        input.entity_length = 0;
        input.entity_sha256 = Sha256::digest(b"").to_vec();
        assert!(empty_only.validate("orders", "orders-api", &input).is_ok());
        input.entity_length = 1;
        assert!(empty_only.validate("orders", "orders-api", &input).is_err());
    }

    #[test]
    fn native_configuration_limits_fail_before_compilation() {
        for change in 0..12 {
            let mut c = configuration(&[], &[]);
            match change {
                0 => c.service = "",
                1 => c.audience = "*",
                2 => c.application = "bad app",
                3 => c.route = "",
                4 => c.route_revision = 0,
                5 => c.route_revision = SAFE + 1,
                6 => c.destination = [0; 32],
                7 => c.header_revision = 0,
                8 => c.header_revision = SAFE + 1,
                9 => c.maximum_entity_bytes = request_binding_v2::MAX_BODY_BYTES as u64 + 1,
                10 => c.headers = &["x-duplicate", "x-duplicate"],
                _ => {
                    c.headers = &["x-private-key"];
                    c.reserved_headers = &["x-private-key"];
                }
            }
            assert!(Scope::compile(c).is_err(), "{change}");
        }
        let mut c = configuration(&[], &[]);
        c.route_revision = SAFE;
        c.header_revision = SAFE;
        assert!(Scope::compile(c).is_ok());
    }
}
