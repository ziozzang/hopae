//! Canonical configured Human scope metadata, never authentication evidence.
//! A source report authenticates this fingerprint for its exact retained proof;
//! consumers must still verify the native source, signature, current owners and
//! lifetime. Reserved filters and entity caps are validation, not bound slots.
use sha2::{Digest as _, Sha256};
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidScope;
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub app_id: &'a str,
    pub route_id: &'a str,
    pub route_revision: u64,
    pub destination_sha256: &'a [u8; 32],
    pub header_policy_revision: u64,
    pub header_names: &'a [&'a str],
    pub reserved_names: &'a [&'a str],
}
pub fn fingerprint(scope: Scope<'_>) -> Result<[u8; 32], InvalidScope> {
    let identifier = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    };
    if ![scope.service, scope.audience, scope.app_id, scope.route_id]
        .into_iter()
        .all(identifier)
        || !(1..=9_007_199_254_740_991).contains(&scope.route_revision)
        || scope.destination_sha256.iter().all(|b| *b == 0)
    {
        return Err(InvalidScope);
    }
    crate::request_binding_v2::HeaderPolicy::new(
        scope.header_policy_revision,
        scope.header_names,
        scope.reserved_names,
    )
    .map_err(|_| InvalidScope)?;
    let mut names = scope.header_names.to_vec();
    names.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"hopae:native-human-scope:v1\0");
    let lp = |hash: &mut Sha256, value: &str| {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value.as_bytes());
    };
    for value in [scope.service, scope.audience, scope.app_id, scope.route_id] {
        lp(&mut hash, value);
    }
    hash.update(scope.route_revision.to_be_bytes());
    hash.update(scope.destination_sha256);
    hash.update(scope.header_policy_revision.to_be_bytes());
    hash.update((names.len() as u16).to_be_bytes());
    for name in names {
        lp(&mut hash, name);
    }
    Ok(hash.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    const DEST: [u8; 32] = [3; 32];
    fn base() -> Scope<'static> {
        Scope {
            service: "orders",
            audience: "orders-api",
            app_id: "app",
            route_id: "owned-route",
            route_revision: 7,
            destination_sha256: &DEST,
            header_policy_revision: 11,
            header_names: &["x-z", "x-a"],
            reserved_names: &["x-auth"],
        }
    }
    #[test]
    fn human_scope_independent_golden_and_canonical_manifest() {
        let expected: [u8; 32] = [
            0x56, 0xc1, 0xc6, 0x29, 0x59, 0x0e, 0xf2, 0x22, 0xc6, 0xb5, 0xe3, 0xe1, 0x1e, 0x83,
            0xba, 0xd9, 0x3c, 0x2e, 0xe7, 0x9b, 0x61, 0xd0, 0x1f, 0x23, 0x97, 0x9c, 0xe6, 0xd7,
            0x76, 0x02, 0xd2, 0xbf,
        ];
        assert_eq!(fingerprint(base()).unwrap(), expected);
        assert_eq!(
            fingerprint(base()),
            fingerprint(Scope {
                header_names: &["x-a", "x-z"],
                ..base()
            })
        );
        // Extra reserved filters do not change an identical allowed slot set.
        assert_eq!(
            fingerprint(base()),
            fingerprint(Scope {
                reserved_names: &["x-auth", "x-other"],
                ..base()
            })
        );
    }
    #[test]
    fn human_scope_every_authority_coordinate_is_bound() {
        let expected = fingerprint(base()).unwrap();
        for scope in [
            Scope {
                service: "other",
                ..base()
            },
            Scope {
                audience: "other",
                ..base()
            },
            Scope {
                app_id: "other",
                ..base()
            },
            Scope {
                route_id: "other",
                ..base()
            },
            Scope {
                route_revision: 8,
                ..base()
            },
            Scope {
                destination_sha256: &[4; 32],
                ..base()
            },
            Scope {
                header_policy_revision: 12,
                ..base()
            },
            Scope {
                header_names: &["x-a"],
                ..base()
            },
        ] {
            assert_ne!(fingerprint(scope).unwrap(), expected);
        }
    }
    #[test]
    fn human_scope_rejects_invalid_configuration() {
        for scope in [
            Scope {
                service: "",
                ..base()
            },
            Scope {
                app_id: "bad\napp",
                ..base()
            },
            Scope {
                route_revision: 0,
                ..base()
            },
            Scope {
                route_revision: 9_007_199_254_740_992,
                ..base()
            },
            Scope {
                destination_sha256: &[0; 32],
                ..base()
            },
            Scope {
                header_policy_revision: 0,
                ..base()
            },
            Scope {
                header_names: &["x-a", "x-a"],
                ..base()
            },
            Scope {
                header_names: &["X-A"],
                ..base()
            },
            Scope {
                header_names: &["authorization"],
                ..base()
            },
            Scope {
                reserved_names: &["x-a"],
                ..base()
            },
        ] {
            assert!(fingerprint(scope).is_err());
        }
    }
}
