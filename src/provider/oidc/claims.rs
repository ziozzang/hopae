//! Mapping validated claims to a [`ProviderIdentity`]: where each field comes
//! from, what counts as a verified email, and when an email is authoritative.
//!
//! Authority rule (ADR-0010, ADR-0011): `email_authoritative` is true only
//! when the ID token itself carries `email_verified: true` and an `hd` claim
//! that is one of the provider's `authoritative_domains` AND the address is in
//! that same domain. `trust_email` can make an address count as verified when
//! the provider sends no flag at all, but never makes it authoritative.

use serde_json::{Map, Value};

use crate::identity::types::NormalizedEmail;
use crate::provider::types::ProviderIdentity;

const MAX_FIELD_BYTES: usize = 256;
const MAX_PICTURE_BYTES: usize = 2048;

pub struct Rules<'a> {
    /// Lower-case domains.
    pub authoritative_domains: &'a [String],
    pub trust_email: bool,
    /// Dotted path of the groups claim when the provider syncs groups.
    pub groups_claim: Option<&'a str>,
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty())
}

/// `true`/`false`, or the strings "true"/"false" some providers send.
fn flag(v: &Value, k: &str) -> Option<bool> {
    match v.get(k)? {
        Value::Bool(b) => Some(*b),
        Value::String(x) if x == "true" => Some(true),
        Value::String(x) if x == "false" => Some(false),
        _ => None,
    }
}

fn cut(x: &str, max: usize) -> String {
    if x.len() <= max {
        return x.to_string();
    }
    let mut end = max;
    while !x.is_char_boundary(end) {
        end -= 1;
    }
    x[..end].to_string()
}

/// `token` is the verified ID token payload; `userinfo` the user-info
/// response whose `sub` has already been checked against the token's.
pub fn build(token: &Value, userinfo: Option<&Value>, rules: &Rules<'_>) -> ProviderIdentity {
    let subject = s(token, "sub").unwrap_or_default().to_string();

    // The email and its verification flag come from one source: the ID token
    // when it has an address, else the user-info response.
    let email_src = if s(token, "email").is_some() {
        Some(token)
    } else {
        userinfo.filter(|u| s(u, "email").is_some())
    };
    let email = email_src
        .and_then(|src| s(src, "email"))
        .and_then(|e| NormalizedEmail::parse(e).ok());
    let claimed = email_src.and_then(|src| flag(src, "email_verified"));
    let email_verified =
        email.is_some() && (claimed == Some(true) || (claimed.is_none() && rules.trust_email));

    let hd = s(token, "hd").map(str::to_ascii_lowercase);
    let email_authoritative = match (&email, &hd) {
        (Some(e), Some(h)) => {
            claimed == Some(true)
                && e.domain() == h
                && rules.authoritative_domains.iter().any(|d| d == h)
        }
        _ => false,
    };

    let pick = |k: &str| {
        s(token, k)
            .or_else(|| userinfo.and_then(|u| s(u, k)))
            .map(|x| cut(x, MAX_FIELD_BYTES))
    };
    let picture = s(token, "picture")
        .or_else(|| userinfo.and_then(|u| s(u, "picture")))
        .filter(|p| p.len() <= MAX_PICTURE_BYTES && p.starts_with("https://"))
        .map(str::to_string);

    let mut raw = Map::new();
    raw.insert("sub".into(), Value::String(cut(&subject, MAX_FIELD_BYTES)));
    for k in ["iss", "hd", "locale"] {
        if let Some(x) = s(token, k) {
            raw.insert(k.into(), Value::String(cut(x, MAX_FIELD_BYTES)));
        }
    }
    if let Some(e) = &email {
        raw.insert("email".into(), Value::String(e.as_str().to_string()));
        raw.insert("email_verified".into(), Value::Bool(email_verified));
    }
    for k in ["name", "preferred_username"] {
        if let Some(x) = pick(k) {
            raw.insert(k.into(), Value::String(x));
        }
    }
    if let Some(p) = &picture {
        raw.insert("picture".into(), Value::String(p.clone()));
    }

    ProviderIdentity {
        subject,
        email,
        email_verified,
        email_authoritative,
        name: pick("name"),
        username: pick("preferred_username"),
        picture,
        raw_claims: Value::Object(raw),
        // A present `null` is a present, invalid claim (ADR-0016 decision 15):
        // it is carried so the validator rejects it, never read as absent.
        auth_time: token.get("auth_time").cloned(),
        // The ID token's claim when present, else the user-info response's
        // (whose `sub` was checked); absent or malformed: not asserted.
        groups: rules.groups_claim.and_then(|path| {
            crate::groups::config::claim_values(token, path)
                .or_else(|| userinfo.and_then(|u| crate::groups::config::claim_values(u, path)))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doms() -> Vec<String> {
        vec!["example.test".to_string()]
    }

    fn rules(d: &[String], trust: bool) -> Rules<'_> {
        Rules {
            authoritative_domains: d,
            trust_email: trust,
            groups_claim: None,
        }
    }

    #[test]
    fn groups_come_from_the_configured_claim_of_the_token_then_userinfo() {
        let mut r = rules(&[], false);
        let t = json!({"sub":"s1","groups":["a","b"],"realm_access":{"roles":["r"]}});
        assert!(build(&t, None, &r).groups.is_none());
        r.groups_claim = Some("groups");
        assert_eq!(build(&t, None, &r).groups.unwrap().len(), 2);
        r.groups_claim = Some("realm_access.roles");
        assert_eq!(build(&t, None, &r).groups.unwrap()[0].key, "r");
        r.groups_claim = Some("teams");
        let ui = json!({"sub":"s1","teams":["t1"]});
        assert_eq!(build(&t, Some(&ui), &r).groups.unwrap()[0].name, "t1");
        assert!(build(&t, None, &r).groups.is_none());
        // Groups never enter the stored raw claims.
        assert!(build(&t, None, &r).raw_claims.get("groups").is_none());
    }

    fn tok() -> Value {
        json!({"sub":"s1","iss":"https://i","email":"A@Example.test","email_verified":true,"name":"Alice","hd":"example.test"})
    }

    #[test]
    fn authoritative_requires_hd_in_list_verified_and_same_domain() {
        let d = doms();
        let id = build(&tok(), None, &rules(&d, false));
        assert!(id.email_authoritative && id.email_verified);
        assert_eq!(id.email.unwrap().as_str(), "A@example.test");

        // hd absent, different, or provider list empty.
        let mut t = tok();
        t.as_object_mut().unwrap().remove("hd");
        assert!(!build(&t, None, &rules(&d, false)).email_authoritative);
        let mut t = tok();
        t["hd"] = json!("other.test");
        assert!(!build(&t, None, &rules(&d, false)).email_authoritative);
        assert!(!build(&tok(), None, &rules(&[], false)).email_authoritative);
        // hd is matched case-insensitively.
        let mut t = tok();
        t["hd"] = json!("EXAMPLE.test");
        assert!(build(&t, None, &rules(&d, false)).email_authoritative);
        // Address outside the hd domain (alias or tampered) is not authoritative.
        let mut t = tok();
        t["email"] = json!("a@gmail.com");
        let id = build(&t, None, &rules(&d, false));
        assert!(id.email_verified && !id.email_authoritative);
        // Unverified is never authoritative.
        let mut t = tok();
        t["email_verified"] = json!(false);
        let id = build(&t, None, &rules(&d, false));
        assert!(!id.email_verified && !id.email_authoritative);
        // A non-string hd is ignored.
        let mut t = tok();
        t["hd"] = json!(["example.test"]);
        assert!(!build(&t, None, &rules(&d, false)).email_authoritative);
    }

    #[test]
    fn hd_only_counts_from_the_signed_token() {
        let d = doms();
        let mut t = tok();
        t.as_object_mut().unwrap().remove("hd");
        let ui =
            json!({"sub":"s1","hd":"example.test","email":"a@example.test","email_verified":true});
        assert!(!build(&t, Some(&ui), &rules(&d, false)).email_authoritative);
    }

    #[test]
    fn trust_email_fills_a_missing_flag_but_never_authority() {
        let d = doms();
        let mut t = tok();
        t.as_object_mut().unwrap().remove("email_verified");
        let id = build(&t, None, &rules(&d, false));
        assert!(!id.email_verified);
        let id = build(&t, None, &rules(&d, true));
        assert!(id.email_verified && !id.email_authoritative);
        // An explicit false is not overridden.
        t["email_verified"] = json!(false);
        assert!(!build(&t, None, &rules(&d, true)).email_verified);
    }

    #[test]
    fn auth_time_is_carried_raw_for_the_portal_to_validate() {
        for raw in [
            json!(1_700_000_000),
            json!("1700000000"),
            json!(-5),
            json!(1.5),
        ] {
            let t = json!({"sub": "s", "auth_time": raw});
            assert_eq!(build(&t, None, &rules(&[], false)).auth_time, Some(raw));
        }
        assert_eq!(
            build(&json!({"sub": "s"}), None, &rules(&[], false)).auth_time,
            None
        );
        assert_eq!(
            build(
                &json!({"sub": "s", "auth_time": null}),
                None,
                &rules(&[], false)
            )
            .auth_time,
            Some(Value::Null),
            "a present null stays present, so the validator rejects it"
        );
    }

    #[test]
    fn string_flags_and_bad_addresses() {
        let d = doms();
        let mut t = tok();
        t["email_verified"] = json!("true");
        assert!(build(&t, None, &rules(&d, false)).email_verified);
        t["email_verified"] = json!("yes");
        assert!(!build(&t, None, &rules(&d, false)).email_verified);
        t["email"] = json!("not an address");
        t["email_verified"] = json!(true);
        let id = build(&t, None, &rules(&d, false));
        assert!(id.email.is_none() && !id.email_verified && !id.email_authoritative);
    }

    #[test]
    fn userinfo_fills_gaps_only() {
        let d = doms();
        let t = json!({"sub":"s1","name":"Token Name"});
        let ui = json!({"sub":"s1","name":"Info Name","email":"b@example.test","email_verified":true,"preferred_username":"bob","picture":"https://x/p.png"});
        let id = build(&t, Some(&ui), &rules(&d, false));
        assert_eq!(id.name.as_deref(), Some("Token Name"));
        assert_eq!(id.username.as_deref(), Some("bob"));
        assert_eq!(id.email.unwrap().as_str(), "b@example.test");
        assert!(id.email_verified && !id.email_authoritative);
        assert_eq!(id.picture.as_deref(), Some("https://x/p.png"));
    }

    #[test]
    fn picture_must_be_https_and_raw_claims_are_bounded_and_token_free() {
        let d = doms();
        let mut t = tok();
        t["picture"] = json!("javascript:alert(1)");
        t["nonce"] = json!("secret-nonce");
        t["name"] = json!("x".repeat(5000));
        t["access_token"] = json!("secret-at");
        let id = build(&t, None, &rules(&d, false));
        assert!(id.picture.is_none());
        let raw = id.raw_claims.to_string();
        assert!(raw.len() < 8 * 1024);
        assert!(!raw.contains("secret"));
        assert!(id.name.unwrap().len() <= 256);
    }
}
