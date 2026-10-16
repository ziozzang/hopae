//! Scenario 900: Kubernetes workload identity (Hangang ADR 0022, P0).
//!
//! Drives the real binary with an offline `kubernetes_workload` profile whose
//! issuer keys are an owned, in-process generated ECDSA JWKS supplied by
//! reference (no network, no cluster). Tokens are minted here exactly as
//! kube-apiserver mints projected ServiceAccount tokens.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::s301_admin_users::kit::{CLIENT_IP, Console};
use super::s307_subject_directory::dkit::{self, console};
use crate::support::*;
use hopae::store::types::AdminRole;

const HOST: &str = "workload.example.test";
const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
const AUDIENCE: &str = "world.hangang.dev/example-cluster";
const JWKS_ENV: &str = "HOPAE_TEST_WORKLOAD_JWKS";
const SPIFFE: &str = "spiffe://cluster.example.test/ns/blue/sa/worker";

struct Key {
    kid: String,
    encoding: jsonwebtoken::EncodingKey,
    jwks: String,
}

fn key(kid: &str) -> Key {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
    ec.public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
        .unwrap();
    let pad = |n: &BigNum| {
        let v = n.to_vec();
        let mut out = vec![0u8; 32 - v.len()];
        out.extend_from_slice(&v);
        URL_SAFE_NO_PAD.encode(out)
    };
    let jwks = json!({"keys": [{"use":"sig","kty":"EC","crv":"P-256","alg":"ES256","kid":kid,"x":pad(&x),"y":pad(&y)}]}).to_string();
    let der = openssl::pkey::PKey::from_ec_key(ec)
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap();
    Key {
        kid: kid.into(),
        encoding: jsonwebtoken::EncodingKey::from_ec_der(&der),
        jwks,
    }
}

fn mint(k: &Key, now: i64, pod: &str, pod_uid: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut claims = json!({
        "iss": ISSUER, "sub": "system:serviceaccount:blue:worker", "aud": [AUDIENCE],
        "exp": now + 3600, "iat": now, "nbf": now,
        "kubernetes.io": {"namespace": "blue",
            "serviceaccount": {"name": "worker", "uid": "sa-uid-1"},
            "pod": {"name": pod, "uid": pod_uid}}
    });
    edit(&mut claims);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(k.kid.clone());
    jsonwebtoken::encode(&header, &claims, &k.encoding).unwrap()
}

fn instance(k: &Key) -> Console {
    let mut apps = dkit::overrides()["apps"].clone();
    apps.as_array_mut()
        .unwrap()
        .push(json!({"app_id": "wl", "display_name": "wl", "hosts": [HOST], "ports": [443]}));
    console(
        json!({
            "apps": apps,
            "authentication_gateway": {"authority_id": "owned", "profiles": [{
                "service_id": "wl", "host": HOST, "ports": [443], "realm": "example-cluster",
                "networks": ["192.0.2.0/24"],
                "kubernetes_workload": {
                    "issuer": ISSUER, "cluster_id": "example-cluster",
                    "trust_domain": "cluster.example.test", "audience": AUDIENCE,
                    "namespaces": ["blue"],
                    "keys": {"source": "static", "jwks_env": JWKS_ENV},
                    "token_prefix": "k8s:"
                }
            }]}
        }),
        &[(JWKS_ENV, &k.jwks)],
    )
}

fn live(k: &Console, token: &str, ip: &str) -> Response {
    k.h.verify(
        VerifyRequest::other(&format!("https://{HOST}/x"))
            .ip(ip)
            .header("authorization", &format!("Bearer k8s:{token}")),
    )
}

/// S900-1: an offline-verified projected token authenticates the
/// ServiceAccount; a rollout keeps the principal; Pod facts stay off the wire.
#[test]
fn s900_1_offline_workload_principal_survives_rollout() {
    let key = key("k1");
    let k = instance(&key);
    let now = k.now_s();
    let first = live(
        &k,
        &mint(&key, now, "worker-5d8f-a", "pod-uid-1", |_| {}),
        CLIENT_IP,
    );
    assert_eq!(first.status, 200, "{first:?}");
    let subject = first.header("x-forwarded-user").unwrap().to_string();
    assert!(subject.starts_with("s_") && subject.len() == 50);
    assert_eq!(first.header("x-hopae-principal-kind"), Some("workload"));
    assert_eq!(first.header("x-hopae-aal"), Some("0"));
    let principal = first.header("x-hopae-principal").unwrap().to_string();
    assert!(principal.starts_with("wk2:") && principal.len() == 68);
    assert_eq!(first.header("x-hopae-workload-spiffe-id"), Some(SPIFFE));
    assert!(!format!("{first:?}").contains("worker-5d8f-a"));
    let rolled = live(
        &k,
        &mint(&key, now, "worker-7c9b-b", "pod-uid-2", |_| {}),
        CLIENT_IP,
    );
    assert_eq!(rolled.status, 200);
    assert_eq!(rolled.header("x-forwarded-user"), Some(subject.as_str()));
    assert_eq!(rolled.header("x-hopae-principal"), Some(principal.as_str()));
}

/// S900-2: wrong audience/issuer, the API-server audience, another key and
/// another namespace are refused without backend identity.
#[test]
fn s900_2_refusals_carry_no_identity() {
    let key = key("k1");
    let other = key_other();
    let k = instance(&key);
    let now = k.now_s();
    for token in [
        mint(&key, now, "p", "u", |c| c["aud"] = json!(["other"])),
        mint(&key, now, "p", "u", |c| {
            c["aud"] = json!([AUDIENCE, "https://kubernetes.default.svc"])
        }),
        mint(&key, now, "p", "u", |c| {
            c["iss"] = json!("https://other.example.test")
        }),
        mint(&other, now, "p", "u", |_| {}),
        mint(&key, now, "p", "u", |c| {
            c["kubernetes.io"]["namespace"] = json!("red");
            c["sub"] = json!("system:serviceaccount:red:worker");
        }),
        mint(&key, now, "p", "u", |c| {
            c.as_object_mut().unwrap().remove("kubernetes.io");
        }),
    ] {
        let r = live(&k, &token, CLIENT_IP);
        assert_eq!(r.status, 401, "{r:?}");
        assert!(r.header("x-forwarded-user").is_none());
        assert!(r.header("x-hopae-principal").is_none());
    }
    // Outside the profile's networks.
    let r = live(&k, &mint(&key, now, "p", "u", |_| {}), "198.51.100.1");
    assert_eq!(r.status, 401);
}

fn key_other() -> Key {
    let mut k = key("k1");
    k.kid = "k1".into();
    k
}

/// S900-8: the lifecycle feed reports the observed principal to consumers
/// that ask for workloads; explain answers like the live path.
#[test]
fn s900_8_lifecycle_feed_and_explain() {
    let key = key("k1");
    let k = instance(&key);
    let a = k.admin("ha500", AdminRole::Viewer);
    let now = k.now_s();
    let r = live(
        &k,
        &mint(&key, now, "worker-pod", "pod-uid-1", |_| {}),
        CLIENT_IP,
    );
    assert_eq!(r.status, 200);
    let principal = r.header("x-hopae-principal").unwrap().to_string();
    let mut found = None;
    for _ in 0..100 {
        let feed = k
            .client(&a)
            .post_json("/v1/subjects/lifecycle", json!({"include_workloads": true}));
        assert_eq!(feed.status, 200, "{feed:?}");
        let body = feed.json();
        if let Some(c) = body["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["change"] == "workload_observed")
        {
            found = Some(c.clone());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let change = found.expect("workload_observed change");
    assert_eq!(change["workload"]["principal"], principal.as_str());
    assert_eq!(change["workload"]["spiffe_id"], SPIFFE);
    assert_eq!(
        change["workload"]["subject_ref"],
        r.header("x-forwarded-user").unwrap()
    );
    assert_eq!(change["status"], "active");
    assert_eq!(change["user_id"], Value::Null);
    // S900-12: after a lost cursor the workload snapshot recovers the
    // principal, with a watermark to continue the feed from.
    let snap = k
        .client(&a)
        .post_json("/v1/subjects/workloads/snapshot", json!({}));
    assert_eq!(snap.status, 200, "{snap:?}");
    let snap = snap.json();
    assert!(snap["watermark"].as_str().unwrap().starts_with("f1."));
    let item = snap["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["principal"] == principal.as_str())
        .expect("principal in snapshot")
        .clone();
    assert_eq!(item["status"], "active");
    assert_eq!(item["spiffe_id"], SPIFFE);
    assert_eq!(item["legacy_subject_refs"], json!([]));
    let bad = k
        .client(&a)
        .post_json("/v1/subjects/workloads/snapshot", json!({"cursor": "l1.5"}));
    assert_eq!(bad.status, 400);
    // Existing consumers (no option) see no workload change.
    let plain = k
        .client(&a)
        .post_json("/v1/subjects/lifecycle", json!({}))
        .json();
    assert!(
        plain["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| !c["change"].as_str().unwrap_or("").starts_with("workload_"))
    );

    for (subject, ip, outcome, code, status) in [
        (SPIFFE, CLIENT_IP, "allow", "allowed", 200),
        (
            "system:serviceaccount:blue:worker",
            CLIENT_IP,
            "allow",
            "allowed",
            200,
        ),
        (
            "spiffe://cluster.example.test/ns/red/sa/worker",
            CLIENT_IP,
            "deny",
            "workload_namespace_not_allowed",
            401,
        ),
        (
            "spiffe://elsewhere.example.test/ns/blue/sa/worker",
            CLIENT_IP,
            "deny",
            "workload_subject_invalid",
            401,
        ),
        (SPIFFE, "198.51.100.1", "deny", "network_denied", 401),
    ] {
        let e = k.client(&a).post_json(
            "/v1/explain/authentication",
            json!({"url": format!("https://{HOST}/x"), "subject": subject, "client_ip": ip, "navigation": "other"}),
        );
        assert_eq!(e.status, 200, "{e:?}");
        let e = e.json();
        assert_eq!(e["outcome"], outcome, "{subject} {ip}: {e}");
        assert_eq!(e["reason"]["code"], format!("hopae.{code}"), "{e}");
        assert_eq!(e["status_code"], status, "{e}");
        assert_eq!(
            e["service_profile"]["connectors"],
            json!(["kubernetes_workload"])
        );
    }
    // The explained allow agrees with the live answer for a real token.
    assert_eq!(
        live(&k, &mint(&key, now, "p2", "u2", |_| {}), CLIENT_IP).status,
        200
    );
}
