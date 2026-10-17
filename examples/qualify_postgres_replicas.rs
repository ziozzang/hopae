//! Two-replica qualification of the PostgreSQL store (ADR-0020 slice 4).
//!
//! Several OS processes run the store operations a Hopae replica performs
//! (login transactions, sign-ins with the user-ID ledger, handoff
//! redemption, fenced administrator writes, the event relay, replay
//! nonces) against ONE PostgreSQL database, on the same shared keys, so
//! they contend; the driver script kills one of them mid-traffic. The
//! verifier then checks, from what the processes logged and from the
//! database, that no effect happened twice and that the ledger is unique.
//!
//! ```text
//! qualify_postgres_replicas setup|work|verify
//!   HOPAE_QUALIFY_PG_URL   connection string (required)
//!   HOPAE_QUALIFY_DIR      directory for setup.json and the replica logs
//!   HOPAE_QUALIFY_REPLICA  replica name (work)
//! ```
//! `tools/qualify_postgres.sh` runs the whole procedure on a tmpfs container.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hopae::crypto::{Clock, Digest, OsRng, Rng, SystemClock, Timestamp, random_id};
use hopae::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use hopae::identity::types::UserId;
use hopae::policy::types::Host;
use hopae::provider::types::{ProviderId, ProviderKind};
use hopae::session::types::{Aal, FactorEntry, FactorKind, SessionId};
use hopae::store::core::{AdminStore, CoreStore, HandoffStore, NonceStore};
use hopae::store::postgres::{PgOptions, PgStore};
use hopae::store::types::*;
use hopae::store::{Deadline, Events};
use sha2::{Digest as _, Sha256};

const TXNS: usize = 1500;
const CODES: usize = 1500;
const SUBJECTS: usize = 400;
const TARGETS: usize = 40;
const EVENTS: usize = 2000;
const HOST: &str = "auth.example.test";
const APP_HOST: &str = "app.example.test";

fn key(kind: &str, i: usize) -> Digest {
    Digest(Sha256::digest(format!("qualify-{kind}-{i}")).into())
}

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("HOPAE_QUALIFY_DIR").expect("HOPAE_QUALIFY_DIR"))
}

async fn connect() -> Arc<PgStore> {
    let url = std::env::var("HOPAE_QUALIFY_PG_URL").expect("HOPAE_QUALIFY_PG_URL");
    Arc::new(
        PgStore::connect(
            PgOptions {
                url,
                ca_pem: None,
                pool_size: 8,
                connect_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(10),
                search_path: None,
            },
            Arc::new(SystemClock),
            Arc::new(OsRng),
            vec!["log".to_string()],
        )
        .await
        .expect("connect"),
    )
}

fn event(kind: EventKind) -> Event {
    EventBuilder::new(&SystemClock, &OsRng, kind, Outcome::Success, "r_qualify").build()
}

fn ip() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}

fn session_row(user: &User, now: Timestamp) -> SessionRow {
    SessionRow {
        session_id: SessionId::new(random_id(&OsRng, "s_")),
        user_id: user.user_id.clone(),
        provider_id: ProviderId::new("mock"),
        auth_time: now,
        factors: vec![FactorEntry {
            kind: FactorKind::Oidc,
            provider: Some(ProviderId::new("mock")),
            at: now,
        }],
        aal: Aal::One,
        authz_version: user.authz_version,
        cred_gen: 1,
        snapshot: IdentitySnapshot {
            email: None,
            display_name: None,
            username: user.username.clone(),
            groups: vec![],
        },
        bound_ip: ip(),
        bound_ua_sha256: None,
        created_at: now,
        last_seen_at: now,
        absolute_expires_at: now.add(Duration::from_secs(86_400)),
        terminated_at: None,
        terminated_reason: None,
        authz_version_at_auth: user.authz_version,
        auth_time_source: AuthTimeSource::HopaeCompletion,
        bound_ua_prefix: None,
    }
}

fn handle_row(session: &SessionId, host: &str, now: Timestamp) -> (HandleRow, Digest) {
    let mut b = [0u8; 32];
    OsRng.fill(&mut b);
    let d = Digest(Sha256::digest(b).into());
    (
        HandleRow {
            handle_sha256: d,
            session_id: session.clone(),
            host: Host::parse(host).unwrap(),
            issued_aal: Aal::One,
            created_at: now,
            last_seen_at: now,
            absolute_expires_at: now.add(Duration::from_secs(86_400)),
            revoked_at: None,
            revoked_reason: None,
        },
        d,
    )
}

async fn new_user(store: &PgStore, name: &str) -> StoreResult<User> {
    store
        .create_user(
            NewUser {
                primary_email: None,
                email_verified: false,
                email_authoritative: false,
                display_name: None,
                username: Some(name.into()),
            },
            NewIdentity {
                provider_id: ProviderId::new("mock"),
                subject: name.into(),
                email: None,
                email_verified: false,
                email_authoritative: false,
                name: None,
                picture: None,
                raw_claims: serde_json::json!({}),
            },
            vec![],
        )
        .await
}

async fn sign_in(store: &PgStore, user: &User) -> (SessionRow, Digest) {
    let now = SystemClock.now();
    let row = session_row(user, now);
    let (h, d) = handle_row(&row.session_id, HOST, now);
    store
        .create_session(CreateSession {
            provider_configuration: None,
            session: row.clone(),
            portal_handle: h,
            portal_handle_digest: d,
            consume_txn: None,
            events: vec![],
        })
        .await
        .expect("session");
    (row, d)
}

use hopae::store::StoreResult;

async fn setup() {
    let store = connect().await;
    store.ensure_realm().await.expect("realm");
    store
        .ensure_provider(ProviderRow {
            provider_id: ProviderId::new("mock"),
            kind: ProviderKind::Oidc,
            display_name: "Mock".into(),
            enabled: true,
            managed_by: ManagedBy::File,
            deleted_at: None,
            sort_order: 0,
            config: serde_json::json!({}),
            client_secret_env: None,
            allowed_email_domains: vec![],
            authoritative_domains: vec![],
            auto_link: false,
            trust_email: false,
        })
        .await
        .expect("provider");
    let now = SystemClock.now();
    let admin = new_user(&store, "qualify-admin").await.expect("admin");
    let (admin_session, admin_handle) = sign_in(&store, &admin).await;
    store
        .grant_admin(
            &admin.user_id,
            AdminRole::Admin,
            GrantManagedBy::Api,
            None,
            "qualify",
            None,
            now,
            event(EventKind::AdminGrant),
        )
        .await
        .expect("grant");
    let mut targets = Vec::new();
    for t in 0..TARGETS {
        let u = new_user(&store, &format!("qualify-target-{t}"))
            .await
            .expect("target");
        let (s1, _) = sign_in(&store, &u).await;
        let (s2, _) = sign_in(&store, &u).await;
        targets.push(serde_json::json!({"user": u.user_id.as_str(), "sessions": [s1.session_id.as_str(), s2.session_id.as_str()]}));
    }
    let holder = new_user(&store, "qualify-handoff").await.expect("holder");
    let (hs, _) = sign_in(&store, &holder).await;
    for i in 0..TXNS {
        store
            .create_transaction_capped(
                NewTransaction {
                    txn_sha256: key("txn", i),
                    created_at: now,
                    expires_at: now.add(Duration::from_secs(3600)),
                    app_id: hopae::policy::types::AppId::new("app"),
                    return_target: url::Url::parse("https://app.example.test/x").unwrap(),
                    bind_sha256: Some(Digest([3; 32])),
                    portal_bind_sha256: None,
                    retry_bind_sha256: None,
                    client_ip: format!("198.51.100.{}", i % 250).parse().unwrap(),
                    ua_sha256: None,
                    provider_id: None,
                    state_sha256: None,
                    nonce: None,
                    pkce_verifier: None,
                    portal_session_id: None,
                    purpose: TxnPurpose::Login,
                    conflicting_handle_sha256: None,
                    pending_identity: None,
                    recovery_depth: 0,
                    reauth_max_age: None,
                },
                vec![],
                Timestamp(now.0 - 60_000),
                None,
                100_000,
            )
            .await
            .expect("txn");
    }
    for i in 0..CODES {
        store
            .mint_handoff_code(
                HandoffCodeRow {
                    code_sha256: key("code", i),
                    session_id: hs.session_id.clone(),
                    host: Host::parse(APP_HOST).unwrap(),
                    return_target: url::Url::parse("https://app.example.test/x").unwrap(),
                    client_ip: ip(),
                    bind_sha256: Digest([8; 32]),
                    issued_aal: Aal::One,
                    cred_gen: hs.cred_gen,
                    recovery_depth: 0,
                    created_at: now,
                    expires_at: now.add(Duration::from_secs(3600)),
                    consumed_at: None,
                    consumed_reason: None,
                },
                vec![],
            )
            .await
            .expect("code");
    }
    for chunk in 0..EVENTS / 100 {
        let batch: Vec<Event> = (0..100)
            .map(|_| {
                EventBuilder::new(
                    &SystemClock,
                    &OsRng,
                    EventKind::LoginFailed,
                    Outcome::Failure,
                    format!("r_q{chunk}"),
                )
                .build()
            })
            .collect();
        CoreStore::append_required(&*store, batch)
            .await
            .expect("events");
    }
    let info = serde_json::json!({
        "admin": admin.user_id.as_str(),
        "admin_session": admin_session.session_id.as_str(),
        "admin_handle": admin_handle.to_hex(),
        "targets": targets,
    });
    std::fs::write(dir().join("setup.json"), info.to_string()).expect("setup.json");
    println!("setup: {TXNS} transactions, {CODES} codes, {TARGETS} targets, {EVENTS} events");
}

/// One line per won effect, written unbuffered: a killed replica loses at
/// most the line of the effect in flight.
struct Log(std::fs::File);
impl Log {
    fn line(&mut self, v: serde_json::Value) {
        let _ = writeln!(self.0, "{v}");
    }
}

async fn work() {
    let replica = std::env::var("HOPAE_QUALIFY_REPLICA").expect("HOPAE_QUALIFY_REPLICA");
    let store = connect().await;
    let info: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir().join("setup.json")).expect("setup.json"),
    )
    .unwrap();
    let mut log = Log(std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir().join(format!("{replica}.log")))
        .expect("log"));
    let actor = Actor {
        user_id: UserId::new(info["admin"].as_str().unwrap()),
        session_id: SessionId::new(info["admin_session"].as_str().unwrap()),
        handle_sha256: Digest::from_hex(info["admin_handle"].as_str().unwrap()).unwrap(),
    };
    let policy = |now| ActorPolicy {
        authority: None,
        console_host: Host::parse(HOST).unwrap(),
        session: Default::default(),
        handle: Default::default(),
        max_auth_age: Duration::from_secs(86_400),
        capability_requires_claim: false,
        require_aal: Aal::One,
        now,
        skew: Duration::from_secs(60),
    };
    let targets = info["targets"].as_array().unwrap().clone();
    // Each replica walks the shared keys in its own order: maximal contention.
    let mut order: Vec<usize> = (0..TXNS).collect();
    let mut seed = Sha256::digest(replica.as_bytes());
    for i in (1..order.len()).rev() {
        seed = Sha256::digest(seed);
        let j = (u64::from_be_bytes(seed[..8].try_into().unwrap()) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let started = Instant::now();
    let (mut won, mut lost) = (0u64, 0u64);
    for i in order {
        let now = SystemClock.now();
        // A login transaction is consumed once.
        if store
            .consume_transaction(&key("txn", i), reasons::OK, now, vec![])
            .await
            .unwrap_or(false)
        {
            log.line(serde_json::json!({"op": "txn", "i": i}));
            won += 1;
        } else {
            lost += 1;
        }
        // A handoff code mints once.
        if i < CODES {
            let (new_handle, _) = handle_row(&SessionId::new("s_placeholder"), APP_HOST, now);
            let req = RedeemRequest {
                code_sha256: key("code", i),
                host: Host::parse(APP_HOST).unwrap(),
                path: "/x".into(),
                client_ip: ip(),
                presented_bind_sha256: Some(Digest([8; 32])),
                presented_handle: None,
                new_handle,
                now,
                max_recoveries: 3,
                session_policy: Default::default(),
                app_lifetimes: Default::default(),
                expiry_events: vec![],
            };
            if let Ok(RedeemOutcome::Minted { .. }) =
                store.redeem_handoff_code(req, vec![], vec![]).await
            {
                log.line(serde_json::json!({"op": "code", "i": i}));
            }
        }
        // A shared subject signs up once: one user, one ledger entry.
        if i < SUBJECTS
            && let Ok(u) = new_user(&store, &format!("qualify-subject-{i}")).await
        {
            log.line(serde_json::json!({"op": "user", "i": i, "user": u.user_id.as_str()}));
        }
        // A nonce is admitted once.
        if store
            .admit_nonce(
                "qualify",
                &format!("n-{i}"),
                now.add(Duration::from_secs(600)),
                now,
                100_000,
            )
            .await
            .unwrap_or(false)
        {
            log.line(serde_json::json!({"op": "nonce", "i": i}));
        }
        // Fenced administrator writes: each target session ends once, each
        // target user is disabled once.
        if i < TARGETS * 2 {
            let t = &targets[i / 2];
            let sid = SessionId::new(t["sessions"][i % 2].as_str().unwrap());
            let mut se = event(EventKind::SessionTerminated);
            se.session_id = Some(sid.clone());
            let deadline = Deadline::after(Duration::from_secs(10));
            if let Ok(true) = store
                .admin_terminate_session(
                    &actor,
                    &policy(now),
                    &sid,
                    deadline,
                    event(EventKind::AdminSessionTerminate),
                    se,
                )
                .await
            {
                log.line(serde_json::json!({"op": "terminate", "session": sid.as_str()}));
            }
        }
        if i < TARGETS {
            let user = UserId::new(targets[i]["user"].as_str().unwrap());
            let mut ae = event(EventKind::AdminUserDisable);
            ae.user_id = Some(user.clone());
            let mk = |s: &SessionRow| {
                let mut e = event(EventKind::SessionTerminated);
                e.session_id = Some(s.session_id.clone());
                e
            };
            if let Ok((true, n)) = store
                .set_user_status(
                    &actor,
                    &policy(now),
                    &user,
                    UserStatus::Disabled,
                    Deadline::after(Duration::from_secs(10)),
                    ae,
                    &mk,
                )
                .await
            {
                log.line(serde_json::json!({"op": "disable", "user": user.as_str(), "ended": n}));
            }
        }
        // The relay: claim a few deliveries, acknowledge them.
        if let Ok(claimed) = store.claim_deliveries("log", 4, now).await {
            for d in claimed {
                log.line(serde_json::json!({"op": "claim", "event": d.event.event_id.as_str(), "attempts": d.attempts}));
                let _ = store.mark_delivered("log", &d.event.event_id, now).await;
            }
        }
    }
    println!(
        "{replica}: done in {:.1}s ({won} transactions won, {lost} lost)",
        started.elapsed().as_secs_f64()
    );
}

async fn verify() -> bool {
    let url = std::env::var("HOPAE_QUALIFY_PG_URL").expect("HOPAE_QUALIFY_PG_URL");
    let (db, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(conn);
    let mut ops: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
    let mut first_claims: BTreeMap<String, u32> = BTreeMap::new();
    let mut replicas = 0;
    for entry in std::fs::read_dir(dir()).expect("dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        replicas += 1;
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            // A killed replica may leave a torn last line.
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let op = v["op"].as_str().unwrap().to_string();
            let k = match op.as_str() {
                "terminate" => v["session"].as_str().unwrap().to_string(),
                "disable" => v["user"].as_str().unwrap().to_string(),
                "claim" => {
                    if v["attempts"].as_u64() == Some(1) {
                        *first_claims
                            .entry(v["event"].as_str().unwrap().to_string())
                            .or_default() += 1;
                    }
                    continue;
                }
                _ => v["i"].to_string(),
            };
            *ops.entry(op).or_default().entry(k).or_default() += 1;
        }
    }
    let mut ok = true;
    let mut check = |what: &str, good: bool| {
        println!("{} {what}", if good { "PASS" } else { "FAIL" });
        ok &= good;
    };
    let dup = |op: &str| {
        ops.get(op)
            .map_or(0, |m| m.values().filter(|n| **n > 1).count())
    };
    for op in ["txn", "code", "user", "nonce", "terminate", "disable"] {
        check(
            &format!(
                "{op}: no effect won twice across replicas ({} won)",
                ops.get(op).map_or(0, |m| m.len())
            ),
            dup(op) == 0,
        );
    }
    check(
        "relay: no delivery handed out twice on its first attempt",
        first_claims.values().all(|n| *n == 1),
    );
    let one = |sql: &str| {
        let db = &db;
        let sql = sql.to_string();
        async move { db.query_one(&sql, &[]).await.unwrap().get::<_, i64>(0) }
    };
    check(
        "transactions: every one consumed, once",
        one("SELECT count(*) FROM login_txns WHERE consumed_at IS NULL").await == 0,
    );
    let codes_won = ops.get("code").map_or(0, |m| m.len()) as i64;
    let codes_consumed =
        one("SELECT count(*) FROM handoff_codes WHERE consumed_at IS NOT NULL").await;
    check(
        &format!(
            "codes: consumed in the store ({codes_consumed}) ≥ minted and logged ({codes_won})"
        ),
        codes_consumed >= codes_won,
    );
    check(
        "ledger: one user per shared subject",
        one("SELECT count(*) FROM (SELECT subject FROM identities WHERE subject LIKE 'qualify-subject-%' GROUP BY subject HAVING count(*) > 1) d").await == 0,
    );
    check(
        "ledger: every user reserved, no reservation reused",
        one("SELECT count(*) FROM users u LEFT JOIN human_user_ids h ON h.user_id = u.user_id WHERE h.user_id IS NULL").await == 0
            && one("SELECT count(*) - count(DISTINCT position) FROM human_user_ids").await == 0,
    );
    let subjects =
        one("SELECT count(*) FROM identities WHERE subject LIKE 'qualify-subject-%'").await;
    let logged_users = ops.get("user").map_or(0, |m| m.len()) as i64;
    check(
        &format!("ledger: users in the store ({subjects}) ≥ logged sign-ups ({logged_users})"),
        subjects >= logged_users,
    );
    check(
        "fences: each target session ended exactly once",
        one("SELECT count(*) FROM (SELECT session_id FROM events WHERE kind = 'session.terminated' AND session_id IS NOT NULL GROUP BY session_id HAVING count(*) > 1) d").await == 0
            && one("SELECT count(*) FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE u.username LIKE 'qualify-target-%' AND s.terminated_at IS NULL").await == 0,
    );
    check(
        "fences: each target disabled exactly once",
        one("SELECT count(*) FROM (SELECT user_id FROM events WHERE kind = 'admin.user_disable' GROUP BY user_id HAVING count(*) > 1) d").await == 0
            && one("SELECT count(*) FROM users WHERE username LIKE 'qualify-target-%' AND status <> 'disabled'").await == 0,
    );
    check(
        "nonces: every admitted nonce is in the shared ledger once",
        one("SELECT count(*) FROM replay_nonces WHERE scope = 'qualify'").await
            >= ops.get("nonce").map_or(0, |m| m.len()) as i64,
    );
    let stuck: BTreeSet<i64> = BTreeSet::from([one(
        "SELECT count(*) FROM event_deliveries WHERE state = 'pending' AND attempts > 0",
    )
    .await]);
    println!(
        "info: {replicas} replica logs; deliveries claimed by a killed replica and not acknowledged (return after the lease): {stuck:?}"
    );
    ok
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("setup") => setup().await,
        Some("work") => work().await,
        Some("verify") => {
            if !verify().await {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: qualify_postgres_replicas setup|work|verify");
            std::process::exit(2);
        }
    }
}
