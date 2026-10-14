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
    ("step_up", Arr(&STEP_UP)),
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
    ("allowed_email_domains", Leaf),
    ("authoritative_domains", Leaf),
    ("auto_link", Leaf),
    ("trust_email", Leaf),
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
    ("users", Arr(&ADMIN_USER)),
]);

pub(super) const ROOT: Node = Obj(&[
    (
        "listen",
        Obj(&[
            ("portal", Leaf),
            ("gateway", Leaf),
            ("admin", Leaf),
            ("native_gateway", Leaf),
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
    (
        "totp_keyring",
        Obj(&[
            ("active_key", Leaf),
            ("keys", Arr(&Obj(&[("id", Leaf), ("key_env", Leaf)]))),
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
