//! Walks the raw JSON against the known key tree so that an unknown key is
//! reported with its path and the nearest known key, and a literal secret is
//! rejected without echoing it (scenarios 013-2 and 013-A4).

use serde_json::Value;

pub(super) enum Node {
    Leaf,
    Obj(&'static [(&'static str, Node)]),
    Arr(&'static Node),
}

use Node::{Arr, Leaf, Obj};

const STEP_UP: Node = Obj(&[
    ("path_prefix", Leaf),
    ("require", Obj(&[("aal", Leaf), ("max_age", Leaf)])),
]);

const APP: Node = Obj(&[
    ("app_id", Leaf),
    ("display_name", Leaf),
    ("hosts", Leaf),
    ("ports", Leaf),
    ("enabled", Leaf),
    ("session", Obj(&[("idle", Leaf), ("absolute", Leaf)])),
    (
        "binding",
        Obj(&[
            ("ip", Leaf),
            ("ip_prefix_v4", Leaf),
            ("ip_prefix_v6", Leaf),
            ("ua", Leaf),
            ("on_mismatch", Leaf),
        ]),
    ),
    ("on_authz_change", Leaf),
    ("verify_cache_seconds", Leaf),
    ("logout_confirm", Leaf),
    ("max_emitted_aal", Leaf),
    ("step_up", Arr(&STEP_UP)),
    (
        "risk",
        Obj(&[
            ("missing", Leaf),
            (
                "rules",
                Arr(&Obj(&[
                    ("path_prefix", Leaf),
                    ("when", Leaf),
                    ("then", Leaf),
                ])),
            ),
        ]),
    ),
]);

const PROVIDER: Node = Obj(&[
    ("provider_id", Leaf),
    ("kind", Leaf),
    ("display_name", Leaf),
    ("enabled", Leaf),
    ("client_id", Leaf),
    (
        "ldap",
        Obj(&[
            ("endpoint", Leaf),
            ("starttls", Leaf),
            ("ca", Leaf),
            ("base_dn", Leaf),
            ("bind_dn", Leaf),
            ("bind_password_env", Leaf),
            ("username_attribute", Leaf),
            ("subject_attribute", Leaf),
            ("subject_encoding", Leaf),
            ("timeout_ms", Leaf),
        ]),
    ),
    ("client_secret_env", Leaf),
    ("issuer", Leaf),
    ("scope", Leaf),
    ("endpoint_hosts", Leaf),
    ("allow_private_endpoints", Leaf),
    (
        "tls",
        Obj(&[
            ("ca_file", Leaf),
            ("client_certificate_file", Leaf),
            ("client_key_file", Leaf),
        ]),
    ),
    (
        "client_assertion",
        Obj(&[
            ("key_file", Leaf),
            ("key_id", Leaf),
            ("algorithms", Leaf),
            ("audience", Leaf),
        ]),
    ),
    ("allowed_email_domains", Leaf),
    ("authoritative_domains", Leaf),
    ("auto_link", Leaf),
    ("trust_email", Leaf),
    (
        "groups",
        Obj(&[
            ("claim", Leaf),
            (
                "ldap",
                Obj(&[
                    ("mode", Leaf),
                    ("member_of_attribute", Leaf),
                    ("search_base_dn", Leaf),
                    ("object_class", Leaf),
                    ("member_attribute", Leaf),
                    ("name_attribute", Leaf),
                ]),
            ),
            ("include", Leaf),
            ("exclude", Leaf),
            ("rewrite", Obj(&[("pattern", Leaf), ("replacement", Leaf)])),
            ("max_groups", Leaf),
            ("removal_grace_secs", Leaf),
            ("sync_interval_secs", Leaf),
            ("sync_batch", Leaf),
        ]),
    ),
]);

const ADMIN_USER: Node = Obj(&[
    ("user_id", Leaf),
    ("email", Leaf),
    ("role", Leaf),
    ("note", Leaf),
]);

const ADMIN: Node = Obj(&[
    (
        "hangang_delegation",
        Obj(&[
            ("key_env", Leaf),
            ("sessions_file", Leaf),
            ("authority", Leaf),
        ]),
    ),
    ("public_url", Leaf),
    ("session", Obj(&[("idle", Leaf), ("absolute", Leaf)])),
    (
        "binding",
        Obj(&[
            ("ip", Leaf),
            ("ip_prefix_v4", Leaf),
            ("ip_prefix_v6", Leaf),
            ("ua", Leaf),
            ("on_mismatch", Leaf),
        ]),
    ),
    ("max_auth_age", Leaf),
    ("require_aal", Leaf),
    ("untrusted_peers", Leaf),
    ("query_budget_ms", Leaf),
    ("directory_privacy", Leaf),
    ("users", Arr(&ADMIN_USER)),
    ("service_audience", Leaf),
]);

pub(super) const ROOT: Node = Obj(&[
    (
        "listen",
        Obj(&[
            ("portal", Leaf),
            ("gateway", Leaf),
            ("admin", Leaf),
            (
                "admin_tls",
                Obj(&[("certificate", Leaf), ("key", Leaf), ("client_ca", Leaf)]),
            ),
            ("native_gateway", Leaf),
            ("grpc_gateway", Leaf),
            (
                "native_gateway_tls",
                Obj(&[("certificate", Leaf), ("key", Leaf), ("client_ca", Leaf)]),
            ),
        ]),
    ),
    (
        "external_verifiers",
        Arr(&Obj(&[
            ("factor", Leaf),
            ("configuration_revision", Leaf),
            ("url", Leaf),
            ("verifier_key_env", Leaf),
            ("timeout_ms", Leaf),
            ("allow_private_endpoints", Leaf),
            ("ca", Leaf),
            ("eligibility_lua", Leaf),
        ])),
    ),
    ("human_material_key_env", Leaf),
    (
        "totp_keyring",
        Obj(&[
            ("active_key", Leaf),
            ("keys", Arr(&Obj(&[("id", Leaf), ("key_env", Leaf)]))),
        ]),
    ),
    (
        "webauthn",
        Obj(&[
            ("rp_id", Leaf),
            ("rp_name", Leaf),
            ("passwordless", Leaf),
            (
                "high_assurance",
                Obj(&[
                    ("attestation_ca_files", Arr(&Leaf)),
                    ("aaguids", Arr(&Leaf)),
                ]),
            ),
        ]),
    ),
    (
        "authentication",
        Obj(&[("source", Leaf), ("reload_interval_ms", Leaf)]),
    ),
    ("reload", Obj(&[("tls_interval_secs", Leaf)])),
    (
        "console_operators",
        Obj(&[
            ("app_id", Leaf),
            ("require_aal", Leaf),
            ("require_factor", Leaf),
            ("step_up_path", Leaf),
            ("step_up_max_age_secs", Leaf),
            ("enrollment_grace_until", Leaf),
            ("assertion_seed_env", Leaf),
            ("assertion_public_key", Leaf),
            ("assertion_key_id", Leaf),
        ]),
    ),
    (
        "risk",
        Obj(&[
            ("context_key_env", Leaf),
            ("context_key_next_env", Leaf),
            ("max_skew_secs", Leaf),
            (
                "memory",
                Obj(&[
                    ("max_sessions", Leaf),
                    ("session_ttl_secs", Leaf),
                    ("max_users", Leaf),
                    ("user_ttl_secs", Leaf),
                    ("countries_per_user", Leaf),
                ]),
            ),
        ]),
    ),
    (
        "authentication_gateway",
        Obj(&[
            ("authority_id", Leaf),
            (
                "profiles",
                Arr(&Obj(&[
                    ("service_id", Leaf),
                    ("host", Leaf),
                    ("ports", Arr(&Leaf)),
                    ("realm", Leaf),
                    (
                        "api_keys",
                        Arr(&Obj(&[
                            ("token_env", Leaf),
                            ("subject", Leaf),
                            ("expires_at", Leaf),
                        ])),
                    ),
                    (
                        "api_relay",
                        Obj(&[
                            ("url", Leaf),
                            ("issuer", Leaf),
                            ("timeout_ms", Leaf),
                            ("allow_private_endpoints", Leaf),
                            ("verifier_key_env", Leaf),
                            ("ca_file", Leaf),
                        ]),
                    ),
                    (
                        "kubernetes_tokenreview",
                        Obj(&[
                            (
                                "connection",
                                Obj(&[
                                    ("api_origin", Leaf),
                                    ("issuer", Leaf),
                                    ("cluster_id", Leaf),
                                    ("audience", Leaf),
                                    ("namespaces", Arr(&Leaf)),
                                    ("timeout_ms", Leaf),
                                ]),
                            ),
                            ("ca_pem_env", Leaf),
                            ("reviewer_token_env", Leaf),
                            ("token_prefix", Leaf),
                            ("trust_domain", Leaf),
                            ("subject", Leaf),
                            ("legacy_until_ms", Leaf),
                            ("legacy_mapping_until_ms", Leaf),
                            ("cache_ttl_ms", Leaf),
                        ]),
                    ),
                    (
                        "kubernetes_workload",
                        Obj(&[
                            ("issuer", Leaf),
                            ("cluster_id", Leaf),
                            ("trust_domain", Leaf),
                            ("audience", Leaf),
                            ("exclusive_audience", Leaf),
                            ("namespaces", Arr(&Leaf)),
                            ("service_accounts", Arr(&Leaf)),
                            ("bound_objects", Arr(&Leaf)),
                            (
                                "keys",
                                Obj(&[
                                    ("source", Leaf),
                                    ("discovery_url", Leaf),
                                    ("jwks_url", Leaf),
                                    ("jwks_origins", Arr(&Leaf)),
                                    ("jwks_env", Leaf),
                                    ("ca_pem_env", Leaf),
                                    ("token_env", Leaf),
                                    ("token_file", Leaf),
                                    ("refresh_seconds", Leaf),
                                    ("max_stale_seconds", Leaf),
                                    ("kid_miss_min_interval_ms", Leaf),
                                    ("timeout_ms", Leaf),
                                ]),
                            ),
                            ("clock_skew_seconds", Leaf),
                            ("max_token_lifetime_seconds", Leaf),
                            ("cache", Obj(&[("ttl_ms", Leaf), ("max_entries", Leaf)])),
                            (
                                "revocation",
                                Obj(&[
                                    ("mode", Leaf),
                                    ("api_origin", Leaf),
                                    ("ca_pem_env", Leaf),
                                    ("token_env", Leaf),
                                    ("token_file", Leaf),
                                    ("resources", Arr(&Leaf)),
                                    ("max_staleness_seconds", Leaf),
                                    ("max_objects", Leaf),
                                ]),
                            ),
                            ("subject", Leaf),
                            ("legacy_until_ms", Leaf),
                            ("legacy_mapping_until_ms", Leaf),
                            ("token_prefix", Leaf),
                        ]),
                    ),
                    (
                        "composition",
                        Obj(&[
                            ("mode", Leaf),
                            ("timeout_ms", Leaf),
                            ("slots", Arr(&Obj(&[("id", Leaf), ("provider", Leaf)]))),
                            (
                                "identities",
                                Arr(&Obj(&[
                                    ("subject", Leaf),
                                    (
                                        "bindings",
                                        Arr(&Obj(&[
                                            ("slot", Leaf),
                                            ("issuer", Leaf),
                                            ("realm", Leaf),
                                            ("subject", Leaf),
                                            ("kind", Leaf),
                                        ])),
                                    ),
                                ])),
                            ),
                        ]),
                    ),
                    ("networks", Arr(&Leaf)),
                    ("session_fallback", Leaf),
                    ("relay_token_prefix", Leaf),
                    ("eligibility_lua", Leaf),
                ])),
            ),
        ]),
    ),
    (
        "projection_receiver",
        Obj(&[
            (
                "workload_observed_scopes",
                Arr(&Obj(&[("service", Leaf), ("audience", Leaf)])),
            ),
            (
                "human_observed_scopes",
                Arr(&Obj(&[
                    ("service", Leaf),
                    ("audience", Leaf),
                    ("application", Leaf),
                    ("route", Leaf),
                ])),
            ),
            (
                "authority",
                Obj(&[
                    ("address", Leaf),
                    ("server_name", Leaf),
                    ("ca", Leaf),
                    ("certificate", Leaf),
                    ("key", Leaf),
                    ("token_env", Leaf),
                ]),
            ),
            (
                "observed_clock_rates",
                Obj(&[("source_ppm", Leaf), ("receiver_ppm", Leaf)]),
            ),
            (
                "secrets",
                Arr(&Obj(&[("reference", Leaf), ("token_env", Leaf)])),
            ),
        ]),
    ),
    (
        "receipt_permit_keys",
        Arr(&Obj(&[
            ("issuer_ref", Leaf),
            ("key_epoch", Leaf),
            ("public_key", Leaf),
        ])),
    ),
    (
        "receipt_issuer",
        Obj(&[
            ("issuer_ref", Leaf),
            ("key_epoch", Leaf),
            ("identity_authority_epoch", Leaf),
            ("public_key", Leaf),
            ("seed_env", Leaf),
            (
                "human_receipts",
                Obj(&[
                    ("source_revision", Leaf),
                    ("capacity", Leaf),
                    ("retained_bytes", Leaf),
                    (
                        "scopes",
                        Arr(&Obj(&[
                            ("service", Leaf),
                            ("audience", Leaf),
                            ("application", Leaf),
                            ("route", Leaf),
                            ("route_revision", Leaf),
                            ("destination_sha256", Leaf),
                            ("header_revision", Leaf),
                            ("headers", Leaf),
                            ("reserved_headers", Leaf),
                            ("maximum_entity_bytes", Leaf),
                        ])),
                    ),
                ]),
            ),
            (
                "workload_receipts",
                Obj(&[
                    ("capacity", Leaf),
                    (
                        "scopes",
                        Arr(&Obj(&[("service", Leaf), ("audience", Leaf)])),
                    ),
                ]),
            ),
            (
                "scopes",
                Arr(&Obj(&[("service", Leaf), ("audience", Leaf)])),
            ),
        ]),
    ),
    (
        "credential_projection",
        Obj(&[
            ("revision", Leaf),
            (
                "plans",
                Arr(&Obj(&[
                    ("service", Leaf),
                    ("audience", Leaf),
                    ("resource", Leaf),
                    ("action", Leaf),
                    ("minimum_aal", Leaf),
                    ("credential", Obj(&[("type", Leaf), ("secret_ref", Leaf)])),
                ])),
            ),
        ]),
    ),
    ("state_dir", Leaf),
    ("store", Obj(&[("kind", Leaf), ("path", Leaf)])),
    (
        "portal",
        Obj(&[("public_url", Leaf), ("sso_confirm_new_host", Leaf)]),
    ),
    (
        "gateway",
        Obj(&[
            ("kind", Leaf),
            ("caller_key_env", Leaf),
            ("caller_key_next_env", Leaf),
            ("allow_unauthenticated_caller", Leaf),
            ("verify_budget_ms", Leaf),
            ("readonly_token_env", Leaf),
            ("admin_url", Leaf),
        ]),
    ),
    (
        "log",
        Obj(&[
            ("level", Leaf),
            ("verify_allow", Leaf),
            ("accept_client_request_id", Leaf),
        ]),
    ),
    ("session", Obj(&[("idle", Leaf), ("absolute", Leaf)])),
    ("cookie", Obj(&[("name", Leaf), ("secure", Leaf)])),
    ("apps", Arr(&APP)),
    ("providers", Arr(&PROVIDER)),
    ("linking", Obj(&[("on_conflict", Leaf), ("mode", Leaf)])),
    (
        "txn",
        Obj(&[("max_rows", Leaf), ("per_ip_per_minute", Leaf)]),
    ),
    (
        "handoff",
        Obj(&[
            ("per_ip_failures_per_minute", Leaf),
            ("max_recoveries", Leaf),
        ]),
    ),
    (
        "events",
        Obj(&[
            ("retention_days", Leaf),
            ("max_rows", Leaf),
            ("prune_every", Leaf),
            ("max_pending_per_sink", Leaf),
            ("delivery_terminal_retention_days", Leaf),
        ]),
    ),
    ("trusted_proxies", Leaf),
    (
        "limits",
        Obj(&[
            ("gateway_max_concurrent", Leaf),
            ("portal_max_concurrent", Leaf),
            ("admin_max_concurrent", Leaf),
        ]),
    ),
    ("sessions", Obj(&[("retention_days", Leaf)])),
    ("admin", ADMIN),
    (
        "groups",
        Obj(&[
            ("max_groups_per_user", Leaf),
            ("change_retention_days", Leaf),
            ("maintenance_interval_secs", Leaf),
            ("stale_group_days", Leaf),
            ("max_staleness_secs", Leaf),
            ("gateway_header", Leaf),
            (
                "projection",
                Obj(&[
                    ("issuer_ref", Leaf),
                    ("key_epoch", Leaf),
                    ("public_key", Leaf),
                    ("seed_env", Leaf),
                    ("audience", Leaf),
                ]),
            ),
        ]),
    ),
]);

/// Collect one message per unknown key, in document order.
pub(super) fn check(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(value, &ROOT, "", &mut out);
    out
}

fn walk(value: &Value, node: &Node, path: &str, out: &mut Vec<String>) {
    match (node, value) {
        (Obj(fields), Value::Object(map)) => {
            for (k, v) in map {
                let here = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match fields.iter().find(|(name, _)| name == k) {
                    Some((_, child)) => walk(v, child, &here, out),
                    None => out.push(unknown(k, &here, fields)),
                }
            }
        }
        (Arr(item), Value::Array(items)) => {
            for (i, v) in items.iter().enumerate() {
                walk(v, item, &format!("{path}[{i}]"), out);
            }
        }
        // A type mismatch is reported by the typed parse that follows.
        _ => {}
    }
}

fn looks_like_literal_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    !k.ends_with("_env")
        && [
            "secret",
            "password",
            "token",
            "api_key",
            "apikey",
            "private_key",
        ]
        .iter()
        .any(|w| k.contains(w))
}

fn unknown(key: &str, path: &str, known: &[(&str, Node)]) -> String {
    if looks_like_literal_secret(key) {
        // Name the key path, never the value.
        return format!(
            "{path}: secrets must be referenced by environment variable name (use a *_env key)"
        );
    }
    let best = known
        .iter()
        .map(|(name, _)| (distance(key, name), *name))
        .min_by_key(|(d, _)| *d);
    match best {
        Some((d, name)) if d <= (key.len() / 3).max(1) => {
            format!("unknown key {path} (did you mean {name}?)")
        }
        _ => format!("unknown key {path}"),
    }
}

/// Levenshtein distance over bytes; keys are short ASCII.
fn distance(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, &ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, &cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_names_path_and_nearest_key() {
        let v: Value = serde_json::json!({
            "apps": [{"app_id": "a", "bindng": {}}],
            "cookie": {"same_site": "lax"},
            "bogus": 1,
        });
        let msgs = check(&v);
        assert!(
            msgs.contains(&"unknown key apps[0].bindng (did you mean binding?)".to_string()),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("unknown key cookie.same_site")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m == "unknown key bogus"), "{msgs:?}");
    }

    #[test]
    fn literal_secret_is_rejected_without_echo() {
        let v: Value =
            serde_json::json!({"providers": [{"provider_id": "g", "client_secret": "hunter2"}]});
        let msgs = check(&v);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("providers[0].client_secret"));
        assert!(msgs[0].contains("environment variable name"));
        assert!(!msgs[0].contains("hunter2"));
    }

    #[test]
    fn valid_tree_has_no_findings() {
        let v: Value = serde_json::json!({"gateway": {"kind": "hangang", "caller_key_env": "X"}, "apps": [{"step_up": [{"require": {"aal": 2}}]}]});
        assert!(check(&v).is_empty());
    }
}
