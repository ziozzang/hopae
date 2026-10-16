//! Scenarios 310-313: groups owned by Hopae (ADR-0019, Hangang ADR 0021):
//! local group administration with compare-and-swap and audit (310), OIDC
//! group sync at sign-in (311), the signed membership projection (312) and
//! group changes in the subject lifecycle feed (313).
//!
//! The tests drive the real binary over the admin listener; people sign in
//! through the real flow against the mock provider.
#![allow(dead_code)]

use base64::Engine;
use serde_json::{Value, json};

use super::s301_admin_users::kit::{Console, Who, code};
use super::s307_subject_directory::dkit::{console, reads};
use crate::support::Response;
use hopae::store::types::AdminRole;

const SEED_ENV: &str = "HOPAE_TEST_GROUPS_SEED";
const SEED: [u8; 32] = [5; 32];

fn post(k: &Console, w: &Who, path: &str, body: Value) -> Response {
    k.client(w).post_json(path, body)
}

fn create(k: &Console, w: &Who, key: &str, name: &str) -> Value {
    let r = post(
        k,
        w,
        "/v1/groups/create",
        json!({"key": key, "name": name, "reason": "fixture"}),
    );
    assert_eq!(r.status, 201, "{r:?}");
    r.json()["group"].clone()
}

fn add(k: &Console, w: &Who, group: &Value, user: &str) -> Value {
    let r = post(
        k,
        w,
        "/v1/groups/members/add",
        json!({"group_id": group["group_id"], "expected_revision": group["revision"], "user_id": user, "reason": "fixture"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    r.json()["group"].clone()
}

fn public_key() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key();
    base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
}

fn projection_console(extra: Value) -> Console {
    let mut v = json!({"groups": {"projection": {
        "issuer_ref": "hopae-groups", "key_epoch": 1, "public_key": public_key(),
        "seed_env": SEED_ENV, "audience": "pumgye"}}});
    if let (Some(a), Some(b)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in b {
            a.insert(k.clone(), val.clone());
        }
    }
    let seed = base64::engine::general_purpose::STANDARD.encode(SEED);
    console(v, &[(SEED_ENV, Box::leak(seed.into_boxed_str()))])
}

fn verify(k: &Console, kind: &str, r: &Response, vocab: &[String]) -> Value {
    assert_eq!(r.status, 200, "{r:?}");
    let key = ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key();
    let keys = |i: &str, e: u64| (i == "hopae-groups" && e == 1).then_some(key);
    let now = k.h.hooks.now_ms();
    hopae::groups::projection::verify(
        &r.body,
        &keys,
        kind,
        "pumgye",
        &hopae::groups::projection::vocabulary_digest(vocab),
        now,
        60_000,
    )
    .unwrap_or_else(|e| panic!("projection page refused: {e}: {}", r.body))
}

fn group_ids(entry: &Value) -> Vec<String> {
    entry["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap().to_string())
        .collect()
}

// ---- 310: local groups ----------------------------------------------------------

#[test]
fn s310_1_local_group_lifecycle_with_cas_and_audit() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha310a", AdminRole::Admin);
    k.add_user("u_g1", "g1.person@example.test", "Group One");
    let g = create(&k, &a, "eng.backend", "Backend");
    let id = g["group_id"].as_str().unwrap().to_string();
    assert!(id.starts_with("grp1:") && id.len() == 31);
    assert_eq!(g["source"], "local");
    assert_eq!(g["revision"], 1);
    assert_eq!(g["members"], 0);
    // The key of a live local group is unique.
    let dup = post(
        &k,
        &a,
        "/v1/groups/create",
        json!({"key": "eng.backend", "name": "Other", "reason": "dup"}),
    );
    assert_eq!(dup.status, 409);
    assert_eq!(code(&dup), "key_in_use");
    // A stale revision is refused with the current one.
    let stale = post(
        &k,
        &a,
        "/v1/groups/update",
        json!({"group_id": id, "expected_revision": 7, "name": "Renamed", "reason": "rename"}),
    );
    assert_eq!(stale.status, 409);
    assert_eq!(code(&stale), "revision_conflict");
    assert_eq!(stale.json()["current_revision"], 1);
    let r = post(
        &k,
        &a,
        "/v1/groups/update",
        json!({"group_id": id, "expected_revision": 1, "name": "Backend team", "description": "On call", "reason": "rename"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let g = r.json()["group"].clone();
    assert_eq!(
        (g["name"].clone(), g["revision"].clone()),
        (json!("Backend team"), json!(2))
    );
    let g = add(&k, &a, &g, "u_g1");
    assert_eq!(
        (g["members"].clone(), g["revision"].clone()),
        (json!(1), json!(3))
    );
    let again = post(
        &k,
        &a,
        "/v1/groups/members/add",
        json!({"group_id": id, "expected_revision": 3, "user_id": "u_g1", "reason": "again"}),
    );
    assert_eq!(code(&again), "already_member");
    let unknown = post(
        &k,
        &a,
        "/v1/groups/members/add",
        json!({"group_id": id, "expected_revision": 3, "user_id": "u_nobody", "reason": "x"}),
    );
    assert_eq!(
        (unknown.status, code(&unknown)),
        (404, "unknown_user".into())
    );
    // Detail with members (masked), a person's groups, resolve with groups.
    let d = post(&k, &a, "/v1/groups/get", json!({"group_id": id}));
    assert_eq!(d.status, 200, "{d:?}");
    let dj = d.json();
    assert_eq!(dj["members"][0]["subject"]["user_id"], "u_g1");
    assert_eq!(dj["members"][0]["subject"]["email"], "g***@example.test");
    assert_eq!(dj["members"][0]["membership"]["reason"], "fixture");
    assert_eq!(
        dj["members"][0]["membership"]["added_by"],
        a.user_id.as_str()
    );
    assert!(!d.body.contains("g1.person@"));
    let mine = post(&k, &a, "/v1/subjects/groups", json!({"id": "u_g1"}));
    assert_eq!(mine.json()["items"][0]["group_id"], id.as_str());
    let res = post(
        &k,
        &a,
        "/v1/subjects/resolve",
        json!({"ids": ["u_g1", "u_never"], "include_groups": true}),
    );
    let rj = res.json();
    assert_eq!(rj["items"][0]["groups"][0]["name"], "Backend team");
    assert_eq!(rj["items"][0]["groups_truncated"], false);
    assert!(rj["items"][1].get("groups").is_none());
    let plain = post(&k, &a, "/v1/subjects/resolve", json!({"ids": ["u_g1"]}));
    assert!(plain.json()["items"][0].get("groups").is_none());
    // Search finds it by name and by key prefix.
    let s = post(&k, &a, "/v1/groups/search", json!({"q": "backend"}));
    assert_eq!(s.json()["items"][0]["group_id"], id.as_str());
    // Remove, delete; a tombstone refuses further writes and keeps resolving.
    let r = post(
        &k,
        &a,
        "/v1/groups/members/remove",
        json!({"group_id": id, "expected_revision": 3, "user_id": "u_g1", "reason": "left"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let r = post(
        &k,
        &a,
        "/v1/groups/delete",
        json!({"group_id": id, "expected_revision": 4, "reason": "retired"}),
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["group"]["state"], "deleted");
    let gone = post(
        &k,
        &a,
        "/v1/groups/update",
        json!({"group_id": id, "expected_revision": 5, "name": "x", "reason": "x"}),
    );
    assert_eq!((gone.status, code(&gone)), (410, "group_deleted".into()));
    assert_eq!(
        post(&k, &a, "/v1/groups/get", json!({"group_id": id})).json()["group"]["state"],
        "deleted"
    );
    // The key is free again for a new group with a new reference.
    let g2 = create(&k, &a, "eng.backend", "Backend");
    assert_ne!(g2["group_id"], id.as_str());
    // Every change is a required group.* event naming the actor and reason.
    let added = k.events("group.member_added");
    let ev = added.last().unwrap();
    assert_eq!(ev["attrs"]["group_id"], id.as_str());
    assert_eq!(ev["attrs"]["actor"], a.user_id.as_str());
    assert_eq!(ev["attrs"]["note"], "fixture");
    assert_eq!(ev["attrs"]["source"], "local");
    assert_eq!(ev["user_id"], "u_g1");
    assert_eq!(k.events("group.created").len(), 2);
    assert_eq!(k.events("group.updated").len(), 1);
    assert_eq!(k.events("group.member_removed").len(), 1);
    assert_eq!(k.events("group.deleted").len(), 1);
}

#[test]
fn s310_2_viewers_read_but_cannot_write() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha310b", AdminRole::Admin);
    let v = k.admin("hv310b", AdminRole::Viewer);
    let g = create(&k, &a, "readers", "Readers");
    let r = post(
        &k,
        &v,
        "/v1/groups/create",
        json!({"key": "x", "name": "X", "reason": "x"}),
    );
    assert_eq!((r.status, code(&r)), (403, "role_insufficient".into()));
    let r = post(&k, &v, "/v1/groups/get", json!({"group_id": g["group_id"]}));
    assert_eq!(r.status, 200);
    assert!(
        reads(&k)
            .iter()
            .any(|e| e["attrs"]["purpose"] == "groups.read")
    );
}

#[test]
fn s310_3_deleting_a_group_with_members_requires_force() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha310e", AdminRole::Admin);
    k.add_user("u_g3", "g3@example.test", "G3");
    let g = create(&k, &a, "full", "Full");
    let g = add(&k, &a, &g, "u_g3");
    let body = |force: bool| json!({"group_id": g["group_id"], "expected_revision": g["revision"], "reason": "retire", "force": force});
    let r = post(&k, &a, "/v1/groups/delete", body(false));
    assert_eq!((r.status, code(&r)), (409, "group_not_empty".into()));
    let r = post(
        &k,
        &a,
        "/v1/groups/delete",
        json!({"group_id": g["group_id"], "expected_revision": g["revision"], "reason": "retire"}),
    );
    assert_eq!(code(&r), "group_not_empty");
    let r = post(&k, &a, "/v1/groups/delete", body(true));
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["group"]["members"], 0);
    let ev = k.events("group.deleted");
    assert_eq!(ev.last().unwrap()["attrs"]["count"], 1);
}

#[test]
fn s310_a1_bodies_and_bounds_are_refused_before_any_write() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha310c", AdminRole::Admin);
    let g = create(&k, &a, "bounded", "Bounded");
    for (path, body) in [
        (
            "/v1/groups/create",
            json!({"key": "a b", "name": "X", "reason": "r"}),
        ),
        (
            "/v1/groups/create",
            json!({"key": "ok", "name": "", "reason": "r"}),
        ),
        ("/v1/groups/create", json!({"key": "ok", "name": "X"})),
        (
            "/v1/groups/create",
            json!({"key": "ok", "name": "X", "reason": "r", "op": "delete"}),
        ),
        (
            "/v1/groups/create",
            json!({"key": "ok", "name": "X", "reason": "x".repeat(257)}),
        ),
        (
            "/v1/groups/update",
            json!({"group_id": g["group_id"], "expected_revision": 1, "reason": "r"}),
        ),
        (
            "/v1/groups/update",
            json!({"group_id": "grp1:bad", "expected_revision": 1, "name": "n", "reason": "r"}),
        ),
        (
            "/v1/groups/members/add",
            json!({"group_id": g["group_id"], "expected_revision": 1, "user_id": "alice", "reason": "r"}),
        ),
        (
            "/v1/groups/members/add",
            json!({"group_id": g["group_id"], "expected_revision": 1, "user_id": "u_x", "reason": "r", "expires_at": 1}),
        ),
        ("/v1/groups/search", json!({"limit": 101})),
        ("/v1/groups/search", json!({"source": "kerberos"})),
        (
            "/v1/groups/get",
            json!({"group_id": g["group_id"], "members_limit": 201}),
        ),
        ("/v1/subjects/groups", json!({"id": "u_x", "limit": 0})),
        ("/v1/groups/search", json!({"cursor": "forged"})),
    ] {
        let r = post(&k, &a, path, body.clone());
        assert_eq!(r.status, 400, "{path} {body}: {r:?}");
    }
    assert_eq!(k.events("group.created").len(), 1);
    assert_eq!(k.events("group.member_added").len(), 0);
}

#[test]
fn s310_a2_per_actor_write_rate_limit() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha310d", AdminRole::Admin);
    let mut last = None;
    for _ in 0..31 {
        last = Some(post(&k, &a, "/v1/groups/create", json!({})));
    }
    let r = last.unwrap();
    assert_eq!(r.status, 429, "{r:?}");
    assert!(r.header("retry-after").is_some());
}

// ---- 311: OIDC group sync -------------------------------------------------------

fn oidc_console() -> Console {
    console(
        json!({"providers": [{"provider_id": "mock", "groups": {
            "claim": "groups", "include": "^eng-", "max_groups": 3,
            "rewrite": {"pattern": "^eng-(.+)$", "replacement": "Engineering $1"}}}]}),
        &[],
    )
}

fn names(k: &Console, a: &Who, user: &str) -> Vec<(String, String)> {
    let r = post(k, a, "/v1/subjects/groups", json!({"id": user}));
    assert_eq!(r.status, 200, "{r:?}");
    let mut v: Vec<(String, String)> = r.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            (
                g["key"].as_str().unwrap().to_string(),
                g["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn s311_1_oidc_claim_is_mapped_filtered_and_synced_at_sign_in() {
    let k = oidc_console();
    let a = k.admin("ha311a", AdminRole::Admin);
    k.idp
        .set_extra_claims(json!({"groups": ["eng-api", "eng-web", "sales"]}));
    let p = k.login("person311", "p311@example.test", "P");
    assert_eq!(
        names(&k, &a, &p.user_id),
        vec![
            ("eng-api".into(), "Engineering api".into()),
            ("eng-web".into(), "Engineering web".into())
        ]
    );
    let r = post(&k, &a, "/v1/subjects/groups", json!({"id": p.user_id}));
    let item = &r.json()["items"][0];
    assert_eq!(item["source"], "oidc");
    assert_eq!(item["provider_id"], "mock");
    assert_eq!(item["membership"]["source"], "oidc");
    // A provider group is not editable by an administrator.
    let gid = item["group_id"].clone();
    let rev = item["revision"].clone();
    let w = post(
        &k,
        &a,
        "/v1/groups/members/remove",
        json!({"group_id": gid, "expected_revision": rev, "user_id": p.user_id, "reason": "x"}),
    );
    assert_eq!((w.status, code(&w)), (409, "group_not_local".into()));
    // The next sign-in no longer asserting eng-web removes it (grace 0).
    k.idp.set_extra_claims(json!({"groups": ["eng-api"]}));
    k.login("person311", "p311@example.test", "P");
    assert_eq!(names(&k, &a, &p.user_id).len(), 1);
    // Too many groups after filtering: refused, nothing changes.
    k.idp
        .set_extra_claims(json!({"groups": ["eng-1", "eng-2", "eng-3", "eng-4"]}));
    k.login("person311", "p311@example.test", "P");
    assert_eq!(
        names(&k, &a, &p.user_id),
        vec![("eng-api".into(), "Engineering api".into())]
    );
    // An absent claim is not an assertion: nothing changes either.
    k.idp.set_extra_claims(json!({}));
    k.login("person311", "p311@example.test", "P");
    assert_eq!(names(&k, &a, &p.user_id).len(), 1);
    // A malformed claim (non-string element) is not an assertion.
    k.idp.set_extra_claims(json!({"groups": ["eng-x", 7]}));
    k.login("person311", "p311@example.test", "P");
    assert_eq!(names(&k, &a, &p.user_id).len(), 1);
    // An empty array is an assertion of no groups.
    k.idp.set_extra_claims(json!({"groups": []}));
    k.login("person311", "p311@example.test", "P");
    assert!(names(&k, &a, &p.user_id).is_empty());
    let removed = k.events("group.member_removed");
    assert!(removed.iter().all(|e| e["attrs"]["cause"] == "login"));
    assert_eq!(removed.len(), 2);
    assert!(
        k.events("group.created")
            .iter()
            .all(|e| e["provider_id"] == "mock")
    );
}

#[test]
fn s311_3_stale_provider_memberships_are_suspended_then_restored() {
    let k = oidc_console();
    let a = k.admin("ha311c", AdminRole::Admin);
    k.idp.set_extra_claims(json!({"groups": ["eng-api"]}));
    let p = k.login("person311c", "p311c@example.test", "P");
    let api = post(&k, &a, "/v1/subjects/groups", json!({"id": p.user_id}));
    assert_eq!(
        api.json()["items"][0]["membership"]["stale_at"],
        Value::Null
    );
    // The console session does not survive the clock jump: read the store.
    let stale = |k: &Console| -> Value {
        let v: Option<i64> = k
            .sql()
            .query_row(
                "SELECT stale_at FROM group_members WHERE user_id = ?1",
                [&p.user_id],
                |r| r.get(0),
            )
            .unwrap();
        v.map_or(Value::Null, Value::from)
    };
    // Eight days without a successful assertion (default bound: 7 days).
    k.h.advance(std::time::Duration::from_secs(8 * 86_400));
    let mut suspended = false;
    for _ in 0..80 {
        if stale(&k).is_i64() {
            suspended = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(suspended, "the maintenance pass suspended the membership");
    assert_eq!(k.events("group.membership_stale").len(), 1);
    // The membership is kept; a sign-in asserting it restores it.
    k.login("person311c", "p311c@example.test", "P");
    assert_eq!(stale(&k), Value::Null);
    assert_eq!(k.events("group.membership_restored").len(), 1);
}

#[test]
fn s311_2_provider_without_groups_section_syncs_nothing() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha311b", AdminRole::Admin);
    k.idp.set_extra_claims(json!({"groups": ["eng-api"]}));
    let p = k.login("person311b", "p311b@example.test", "P");
    assert!(names(&k, &a, &p.user_id).is_empty());
    assert!(k.events("group.created").is_empty());
}

// ---- 312: the signed membership projection ---------------------------------------

#[test]
fn s312_1_snapshot_and_changes_are_signed_bounded_and_resumable() {
    let k = projection_console(json!({}));
    let a = k.admin("ha312a", AdminRole::Admin);
    for u in ["u_pa", "u_pb", "u_pc"] {
        k.add_user(u, &format!("{u}@example.test"), u);
    }
    let g1 = create(&k, &a, "relevant", "Relevant");
    let g2 = create(&k, &a, "irrelevant", "Irrelevant");
    let g1 = add(&k, &a, &g1, "u_pa");
    let g1 = add(&k, &a, &g1, "u_pb");
    let g2 = add(&k, &a, &g2, "u_pc");
    let vocab = vec![g1["group_id"].as_str().unwrap().to_string()];
    let first = post(
        &k,
        &a,
        "/v1/groups/projection/snapshot",
        json!({"groups": vocab, "limit": 1}),
    );
    let p1 = verify(&k, "snapshot", &first, &vocab);
    assert_eq!(p1["kind"], "snapshot");
    assert_eq!(p1["max_aal"], 2);
    assert_eq!(p1["entries"].as_array().unwrap().len(), 1);
    assert_eq!(p1["cursor"], Value::Null);
    let watermark = p1["watermark"].as_i64().unwrap();
    let next = p1["next_cursor"].as_str().unwrap().to_string();
    let p2 = verify(
        &k,
        "snapshot",
        &post(
            &k,
            &a,
            "/v1/groups/projection/snapshot",
            json!({"groups": vocab, "cursor": next.clone(), "limit": 1}),
        ),
        &vocab,
    );
    assert_eq!(p2["more"], false);
    assert_eq!(p2["cursor"], next.as_str());
    assert_eq!(p2["watermark"], watermark);
    let users: Vec<&str> = [&p1, &p2]
        .iter()
        .flat_map(|p| p["entries"].as_array().unwrap().iter())
        .map(|e| e["user_id"].as_str().unwrap())
        .collect();
    assert_eq!(users, ["u_pa", "u_pb"]);
    assert_eq!(group_ids(&p1["entries"][0]), vocab);
    assert!(!first.body.contains("u_pc"));
    // Without Human receipts the principal is null (not bindable).
    assert_eq!(p1["entries"][0]["principal"], Value::Null);
    // Changes after the watermark, restricted to the vocabulary.
    let r = post(
        &k,
        &a,
        "/v1/groups/members/remove",
        json!({"group_id": g1["group_id"], "expected_revision": g1["revision"], "user_id": "u_pa", "reason": "left"}),
    );
    assert_eq!(r.status, 200);
    add(&k, &a, &g2, "u_pa");
    let ch = verify(
        &k,
        "changes",
        &post(
            &k,
            &a,
            "/v1/groups/projection/changes",
            json!({"groups": vocab, "cursor": format!("r{watermark}")}),
        ),
        &vocab,
    );
    assert_eq!(ch["kind"], "changes");
    let changes = ch["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{ch}");
    assert_eq!(changes[0]["change"], "member_removed");
    assert_eq!(changes[0]["user_id"], "u_pa");
    assert_eq!(ch["more"], false);
    // A vocabulary digest binds the page: another vocabulary does not verify.
    let other = vec![g2["group_id"].as_str().unwrap().to_string()];
    let page = post(
        &k,
        &a,
        "/v1/groups/projection/snapshot",
        json!({"groups": other}),
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key();
    assert!(
        hopae::groups::projection::verify(
            &page.body,
            &|_, _| Some(key),
            "snapshot",
            "pumgye",
            &hopae::groups::projection::vocabulary_digest(&vocab),
            k.h.hooks.now_ms(),
            60_000,
        )
        .is_err()
    );
    // A page signed by another key is refused.
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[6; 32]).verifying_key();
    assert!(
        hopae::groups::projection::verify(
            &first.body,
            &|_, _| Some(wrong),
            "snapshot",
            "pumgye",
            &hopae::groups::projection::vocabulary_digest(&vocab),
            k.h.hooks.now_ms(),
            60_000,
        )
        .is_err()
    );
    assert!(
        reads(&k)
            .iter()
            .any(|e| e["attrs"]["purpose"] == "groups.projection")
    );
}

#[test]
fn s312_a1_pruned_or_foreign_revisions_and_bad_vocabularies_are_refused() {
    let k = projection_console(json!({}));
    let a = k.admin("ha312b", AdminRole::Admin);
    let g = create(&k, &a, "pruned", "Pruned");
    let vocab = vec![g["group_id"].as_str().unwrap().to_string()];
    for body in [
        json!({"groups": []}),
        json!({"groups": ["grp1:bad"]}),
        json!({"groups": vec![vocab[0].clone(); 1025]}),
        json!({"groups": vocab, "cursor": "x"}),
        json!({"groups": vocab, "limit": 501}),
    ] {
        assert_eq!(
            post(&k, &a, "/v1/groups/projection/changes", body.clone()).status,
            400,
            "{body}"
        );
    }
    let r = post(
        &k,
        &a,
        "/v1/groups/projection/changes",
        json!({"groups": vocab, "cursor": "r999999"}),
    );
    assert_eq!((r.status, code(&r)), (410, "cursor_expired".into()));
    create(&k, &a, "later", "Later");
    k.sql()
        .execute(
            "DELETE FROM group_changes WHERE revision < (SELECT MAX(revision) FROM group_changes)",
            [],
        )
        .unwrap();
    let r = post(
        &k,
        &a,
        "/v1/groups/projection/changes",
        json!({"groups": vocab, "cursor": "r0"}),
    );
    assert_eq!((r.status, code(&r)), (410, "cursor_expired".into()));
}

#[test]
fn s312_a2_projection_without_a_key_is_unavailable() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha312c", AdminRole::Admin);
    let g = create(&k, &a, "nokey", "No key");
    let r = post(
        &k,
        &a,
        "/v1/groups/projection/snapshot",
        json!({"groups": [g["group_id"]]}),
    );
    assert_eq!((r.status, code(&r)), (503, "projection_unavailable".into()));
}

// ---- 313: group changes in the lifecycle feed ------------------------------------

#[test]
fn s313_1_lifecycle_feed_reports_group_changes_only_when_asked() {
    let k = console(json!({}), &[]);
    let a = k.admin("ha313a", AdminRole::Admin);
    k.add_user("u_lf", "lf@example.test", "Lf");
    let watermark = post(&k, &a, "/v1/subjects/lifecycle/snapshot", json!({})).json()["watermark"]
        .as_str()
        .unwrap()
        .to_string();
    let g = create(&k, &a, "feed", "Feed");
    add(&k, &a, &g, "u_lf");
    let plain = post(
        &k,
        &a,
        "/v1/subjects/lifecycle",
        json!({"cursor": watermark}),
    );
    assert_eq!(plain.json()["changes"], json!([]));
    let with = post(
        &k,
        &a,
        "/v1/subjects/lifecycle",
        json!({"cursor": watermark, "include_groups": true}),
    );
    assert_eq!(with.status, 200, "{with:?}");
    let changes = with.json()["changes"].as_array().unwrap().clone();
    let summary: Vec<(String, Value, Value, String)> = changes
        .iter()
        .map(|c| {
            (
                c["change"].as_str().unwrap().to_string(),
                c["user_id"].clone(),
                c["group_id"].clone(),
                c["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "group_created".into(),
                Value::Null,
                g["group_id"].clone(),
                "active".into()
            ),
            (
                "member_added".into(),
                json!("u_lf"),
                g["group_id"].clone(),
                "active".into()
            ),
        ]
    );
}
