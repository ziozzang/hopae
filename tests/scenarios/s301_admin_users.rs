//! Scenario 301: console users — list, search, detail, disable and enable.
//!
//! The tests drive the real binary over the admin listener. Administrators
//! sign in through the real portal flow for the console host and are granted
//! with the store's own `grant_admin`; bulk rows come from the test hooks and
//! direct SQL against the instance's database file. `kit` is shared with the
//! 302 and 303 files.
#![allow(dead_code)]

use serde_json::{Value, json};

use crate::support::*;

pub(crate) mod kit {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use hopae::crypto::{OsRng, Secret, TestClock, Timestamp, handle_value};
    use hopae::event::types::{EventBuilder, EventKind, Outcome};
    use hopae::identity::types::UserId;
    use hopae::store::Store;
    use hopae::store::types::{AdminRole, GrantManagedBy};
    use serde_json::{Value, json};

    use crate::support::*;

    pub const CLIENT_IP: &str = "192.0.2.10";

    /// A running instance with the console, its mock provider and helpers.
    pub struct Console {
        pub h: Hopae,
        pub idp: MockIdp,
    }

    /// A signed-in console user.
    #[derive(Clone)]
    pub struct Who {
        pub user_id: String,
        pub handle: String,
    }

    impl Console {
        pub fn new() -> Console {
            Console::with(json!({}))
        }

        pub fn with(overrides: Value) -> Console {
            let idp = MockIdp::start("default");
            let h = Hopae::spawn(Fixture::with("m4-admin", overrides), &idp, &[]);
            Console { h, idp }
        }

        pub fn db_path(&self) -> PathBuf {
            self.h.state_dir.path().join("state/hopae.db")
        }

        /// A direct connection to the instance's database (WAL; short waits).
        pub fn sql(&self) -> rusqlite::Connection {
            let c = rusqlite::Connection::open(self.db_path()).expect("open the database");
            c.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
            c
        }

        pub fn now_s(&self) -> i64 {
            self.h.hooks.now_ms() / 1000
        }

        pub fn count(&self, sql: &str) -> i64 {
            self.sql().query_row(sql, [], |r| r.get(0)).expect("count")
        }

        /// Start a console sign-in up to the handoff: returns the application
        /// URL carrying the handoff code and the binding cookie value, or the
        /// callback's own answer when it was not a login.
        pub fn begin_login(
            &self,
            sub: &str,
            email: &str,
            name: &str,
        ) -> Result<(String, String), Response> {
            static SUBJECT: Mutex<()> = Mutex::new(());
            let h = &self.h;
            self.idp.set_user(sub, email, true, name);
            let r = h.verify(
                VerifyRequest::document("https://hopae-admin.example.test/users").ip(CLIENT_IP),
            );
            assert_eq!(r.status, 302, "{r:?}");
            let loc = url::Url::parse(r.location().expect("location")).unwrap();
            let txn = loc
                .query_pairs()
                .find(|(k, _)| k == "txn")
                .map(|(_, v)| v.into_owned())
                .expect("txn");
            let bind = r
                .set_cookies()
                .iter()
                .find_map(|c| c.strip_prefix("__Host-hopae_bind="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
                .expect("binding cookie");
            let c = h.portal().with_ip(CLIENT_IP);
            let page = c.get(&format!("/login?txn={txn}"));
            let go = if page.status == 302 {
                page
            } else {
                let csrf = page
                    .body
                    .split("name=\"csrf\" value=\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or_default()
                    .to_string();
                c.post_form("/login/mock", &[("csrf", &csrf), ("txn", &txn)])
            };
            assert_eq!(go.status, 302, "{go:?}");
            let callback = {
                let _g = SUBJECT.lock().unwrap_or_else(|p| p.into_inner());
                self.idp.set_subject(sub);
                self.idp
                    .follow_authorization(go.location().expect("provider redirect"))
            };
            let cb = c.get(&callback);
            if cb.status != 302 {
                return Err(cb);
            }
            Ok((cb.location().expect("handoff redirect").to_string(), bind))
        }

        /// Redeem the handoff code at the console host.
        pub fn redeem(&self, url: &str, bind: &str) -> Response {
            self.h.verify(
                VerifyRequest::document(url)
                    .ip(CLIENT_IP)
                    .cookie("__Host-hopae_bind", bind),
            )
        }

        /// Sign `sub` in at the console host through the portal and the
        /// provider; returns the callback's answer and the redeeming verify's.
        pub fn login_raw(
            &self,
            sub: &str,
            email: &str,
            name: &str,
        ) -> (Response, Option<Response>) {
            match self.begin_login(sub, email, name) {
                Err(cb) => (cb, None),
                Ok((url, bind)) => {
                    let redeem = self.redeem(&url, &bind);
                    let cb = Response {
                        status: 302,
                        headers: Vec::new(),
                        body: String::new(),
                    };
                    (cb, Some(redeem))
                }
            }
        }

        /// Sign in; returns the user id and the console handle.
        pub fn login(&self, sub: &str, email: &str, name: &str) -> Who {
            let (_, redeem) = self.login_raw(sub, email, name);
            let redeem = redeem.expect("the login completed");
            let handle = redeem
                .set_cookies()
                .iter()
                .find_map(|c| c.strip_prefix("__Host-hopae="))
                .map(|rest| rest.split(';').next().unwrap_or("").to_string())
                .unwrap_or_else(|| panic!("no console handle planted: {redeem:?}"));
            let ev = self.h.hooks.events(Some("login.succeeded"), Some(100_000));
            let user_id = ev
                .iter()
                .filter(|e| e["user_id"].is_string())
                .max_by_key(|e| e["event_id"].as_str().unwrap_or("").to_string())
                .and_then(|e| e["user_id"].as_str())
                .expect("a login.succeeded event")
                .to_string();
            Who { user_id, handle }
        }

        /// Grant `role` to a user the way the command line does.
        pub fn grant(&self, user_id: &str, role: AdminRole) {
            let clock = Arc::new(TestClock::new(Timestamp(self.h.hooks.now_ms())));
            let store = Store::open_cli(&self.db_path(), clock.clone(), vec![]).expect("open_cli");
            let uid = UserId::new(user_id);
            let ev = EventBuilder::new(
                clock.as_ref(),
                &OsRng,
                EventKind::AdminGrant,
                Outcome::Success,
                "r_kit",
            )
            .user(&uid)
            .attr("actor", "cli")
            .attr("role", role.as_str())
            .attr("managed_by", "api")
            .build();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                store
                    .directory()
                    .grant_admin(
                        &uid,
                        role,
                        GrantManagedBy::Api,
                        None,
                        "cli",
                        None,
                        Timestamp(self.h.hooks.now_ms()),
                        ev,
                    )
                    .await
                    .expect("grant_admin");
            });
        }

        /// A signed-in user with a grant.
        pub fn admin(&self, sub: &str, role: AdminRole) -> Who {
            let w = self.login(sub, &format!("{sub}@admin.test"), sub);
            self.grant(&w.user_id, role);
            w
        }

        pub fn client(&self, w: &Who) -> AdminClient<'_> {
            self.h.admin_client().with_handle(&w.handle)
        }

        // ---- fixtures ---------------------------------------------------

        pub fn add_user(&self, id: &str, email: &str, name: &str) {
            let now = self.now_s();
            self.sql()
                .execute(
                    "INSERT INTO users (user_id, primary_email, email_verified, display_name, status, created_at, updated_at) VALUES (?1, ?2, 1, ?3, 'active', ?4, ?4)",
                    rusqlite::params![id, email, name, now],
                )
                .expect("add_user");
        }

        pub fn add_identity(&self, user: &str, provider: &str, subject: &str, email: &str) {
            let now = self.now_s();
            self.sql()
                .execute(
                    "INSERT INTO identities (provider_id, subject, user_id, email, email_verified, name, picture, raw_claims, first_seen_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, 1, 'Name', 'https://pic.example/x', '{\"secret_claim\":\"zzz\"}', ?5, ?5)",
                    rusqlite::params![provider, subject, user, email, now],
                )
                .expect("add_identity");
        }

        /// A session of `user` created at `created` (unix seconds) with one
        /// handle per host; returns the handle values in host order.
        #[allow(clippy::too_many_arguments)]
        pub fn add_session(
            &self,
            id: &str,
            user: &str,
            created: i64,
            ip: &str,
            ua_prefix: Option<&str>,
            hosts: &[&str],
            terminated: Option<(i64, &str)>,
            absolute_expires_at: Option<i64>,
        ) -> Vec<String> {
            let c = self.sql();
            let exp = absolute_expires_at.unwrap_or(created + 2_592_000);
            c.execute(
                "INSERT INTO sessions (session_id, user_id, provider_id, auth_time, aal, authz_version, cred_gen, bound_ip, created_at, last_seen_at, absolute_expires_at, authz_version_at_auth, auth_time_source, bound_ua_prefix, terminated_at, terminated_reason)
                 SELECT ?1, user_id, 'mock', ?3, 1, authz_version, 1, ?4, ?3, ?3, ?5, authz_version, 'hopae_completion', ?6, ?7, ?8 FROM users WHERE user_id = ?2",
                rusqlite::params![
                    id,
                    user,
                    created,
                    ip,
                    exp,
                    ua_prefix,
                    terminated.map(|t| t.0),
                    terminated.map(|t| t.1)
                ],
            )
            .expect("add_session");
            let mut out = Vec::new();
            for host in hosts {
                let v: Secret = handle_value(&OsRng);
                let d = v.digest();
                c.execute(
                    "INSERT INTO session_handles (handle_sha256, session_id, host, issued_aal, created_at, last_seen_at, absolute_expires_at, revoked_at, revoked_reason) VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        &d.0[..],
                        id,
                        host,
                        created,
                        created + 604_800,
                        terminated.map(|t| t.0),
                        terminated.map(|_| "session_terminated")
                    ],
                )
                .expect("add handle");
                out.push(v.expose().to_string());
            }
            out
        }

        /// `n` events of `kind` for the given columns, one second apart ending
        /// at `end` (unix seconds), ids `e_kit<tag><n>`.
        #[allow(clippy::too_many_arguments)]
        pub fn add_events(
            &self,
            tag: &str,
            n: i64,
            kind: &str,
            outcome: &str,
            user: Option<&str>,
            session: Option<&str>,
            ip: Option<&str>,
            end: i64,
        ) {
            let mut c = self.sql();
            let tx = c.transaction().unwrap();
            {
                let mut st = tx
                    .prepare(
                        "INSERT INTO events (event_id, at, kind, outcome, user_id, session_id, client_ip, request_id, attrs) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'r_kit', '{}')",
                    )
                    .unwrap();
                for i in 0..n {
                    st.execute(rusqlite::params![
                        format!("e_kit{tag}{i:08}"),
                        (end - (n - 1 - i)) as f64,
                        kind,
                        outcome,
                        user,
                        session,
                        ip
                    ])
                    .unwrap();
                }
            }
            tx.commit().unwrap();
        }

        pub fn count_text(&self, sql: &str) -> String {
            self.sql().query_row(sql, [], |r| r.get(0)).expect("text")
        }

        pub fn metric(&self, series: &str) -> i64 {
            self.h.hooks.counters()["metrics"][series]
                .as_i64()
                .unwrap_or(0)
        }

        pub fn events(&self, kind: &str) -> Vec<Value> {
            self.h.hooks.events(Some(kind), Some(100_000))
        }

        pub fn origin(&self) -> String {
            self.h.console_origin()
        }
    }

    /// Every item from the page at `first_cursor` (the first page when `None`)
    /// to the end; `path` carries no `cursor` parameter.
    pub fn walk_from(cl: &AdminClient<'_>, path: &str, first_cursor: Option<&str>) -> Vec<Value> {
        let mut items = Vec::new();
        let mut cursor = first_cursor.map(str::to_string);
        for _ in 0..5000 {
            let url = match &cursor {
                None => path.to_string(),
                Some(c) => format!(
                    "{path}{}cursor={}",
                    if path.contains('?') { '&' } else { '?' },
                    url::form_urlencoded::byte_serialize(c.as_bytes()).collect::<String>()
                ),
            };
            let r = cl.get(&url);
            assert_eq!(r.status, 200, "{url}: {}", r.body);
            let j = r.json();
            items.extend(j["items"].as_array().cloned().unwrap_or_default());
            match j["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => return items,
            }
        }
        panic!("the walk of {path} does not end");
    }

    /// Follow `next_cursor` to the end; returns how many pages it took.
    pub fn walk_pages(cl: &AdminClient<'_>, path: &str) -> usize {
        let mut pages = 0;
        let mut cursor: Option<String> = None;
        loop {
            let url = match &cursor {
                None => path.to_string(),
                Some(c) => format!(
                    "{path}{}cursor={}",
                    if path.contains('?') { '&' } else { '?' },
                    url::form_urlencoded::byte_serialize(c.as_bytes()).collect::<String>()
                ),
            };
            let r = cl.get(&url);
            assert_eq!(r.status, 200, "{url}: {}", r.body);
            pages += 1;
            assert!(pages < 5000, "the walk of {path} does not end");
            match r.json()["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => return pages,
            }
        }
    }

    /// The `{"error": code}` of a response.
    pub fn code(r: &Response) -> String {
        r.json()["error"].as_str().unwrap_or("").to_string()
    }
}

use hopae::store::types::AdminRole;
use kit::{Console, code};

const USER_FIELDS: [&str; 12] = [
    "user_id",
    "primary_email",
    "email_verified",
    "email_authoritative",
    "display_name",
    "username",
    "status",
    "authz_version",
    "created_at",
    "last_login_at",
    "live_sessions",
    "role",
];

fn ids(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|i| i["user_id"].as_str().expect("user_id").to_string())
        .collect()
}

#[test]
fn s301_1_users_listed_newest_first_in_pages() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_users(229); // 230 users with the administrator
    let c = k.client(&a);

    let r = c.get("/v1/users");
    assert_eq!(r.status, 200, "{}", r.body);
    let j = r.json();
    let first = j["items"].as_array().unwrap().clone();
    assert_eq!(first.len(), 50);
    for item in &first {
        for f in USER_FIELDS {
            assert!(item.get(f).is_some(), "{f} missing in {item}");
        }
    }
    // Ordered by created_at DESC, user_id DESC.
    let key = |v: &Value| {
        (
            v["created_at"].as_i64().unwrap(),
            v["user_id"].as_str().unwrap().to_string(),
        )
    };
    assert!(
        first.windows(2).all(|w| key(&w[0]) >= key(&w[1])),
        "newest first"
    );
    // The administrator has a grant; a bulk user has none.
    let me = first.iter().find(|i| i["user_id"] == a.user_id.as_str());
    if let Some(me) = me {
        assert_eq!(me["role"], "admin");
    }
    assert!(
        first.iter().any(|i| i["role"].is_null()),
        "users without a grant have role null"
    );
    assert!(j["next_cursor"].is_string());

    // The pages together hold every user exactly once.
    let all = c.walk_rows("/v1/users", 230);
    let mut seen = ids(&all);
    assert_eq!(seen.len(), 230);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 230, "no user twice");

    // limit=200 gives 200 and then 30.
    let r = c.get("/v1/users?limit=200").json();
    assert_eq!(r["items"].as_array().unwrap().len(), 200);
    let cursor = r["next_cursor"].as_str().expect("cursor").to_string();
    let enc: String = url::form_urlencoded::byte_serialize(cursor.as_bytes()).collect();
    let r2 = c.get(&format!("/v1/users?limit=200&cursor={enc}")).json();
    assert_eq!(r2["items"].as_array().unwrap().len(), 30);

    // The page shows the same first 50 rows and a next link carrying the cursor.
    let page = c.get("/users");
    assert_eq!(page.status, 200);
    assert!(
        page.header("content-type")
            .unwrap_or("")
            .starts_with("text/html")
    );
    for id in ids(&first) {
        assert!(
            page.body.contains(&format!("/users/{id}")),
            "{id} on the page"
        );
    }
    let extra = &ids(&all)[50];
    assert!(
        !page.body.contains(&format!("/users/{extra}\"")),
        "only 50 rows"
    );
    assert!(page.body.contains("rel=\"next\""), "next link");
    assert!(
        page.body.contains("cursor="),
        "next link carries the cursor"
    );

    // One range scan of users(created_at, user_id).
    let e = k.h.hooks.explain("users", true);
    let plan = e["plan"].to_string();
    assert!(plan.contains("users_created_id"), "{plan}");
    assert_eq!(e["sort"], 0, "no sort: {e}");
}

/// Give bulk user `n` (1-based) an address `user<n>@example.test`.
fn rename_bulk(k: &Console, n: i64, email: &str) {
    k.sql()
        .execute(
            "UPDATE users SET primary_email = ?2 WHERE user_id = printf('u_blk%09d', ?1)",
            rusqlite::params![n, email],
        )
        .unwrap();
}

#[test]
fn s301_2_search_prefix_and_substring_inside_window() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_users(229);
    {
        let c = k.sql();
        c.execute(
            "UPDATE users SET primary_email = printf('user%d@example.test', CAST(substr(user_id, 6) AS INTEGER)) WHERE user_id LIKE 'u_blk%'",
            [],
        )
        .unwrap();
        c.execute(
            "UPDATE users SET display_name = NULL WHERE user_id LIKE 'u_blk%'",
            [],
        )
        .unwrap();
        c.execute(
            "UPDATE users SET display_name = 'Kim ' || user_id WHERE CAST(substr(user_id, 6) AS INTEGER) BETWEEN 200 AND 211",
            [],
        )
        .unwrap();
        c.execute(
            "UPDATE users SET status = 'disabled' WHERE CAST(substr(user_id, 6) AS INTEGER) IN (11, 12, 150, 205)",
            [],
        )
        .unwrap();
    }
    rename_bulk(&k, 7, "x@example.test");
    let cl = k.client(&a);
    let series = "hopae_admin_rows_examined_total{list=\"users\"}";
    let total_users = k.count("SELECT COUNT(*) FROM users");
    // Walk a query page by page, bounding what each request examined.
    let walk = |path: &str| -> Vec<Value> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let url = match &cursor {
                None => path.to_string(),
                Some(c) => format!(
                    "{path}&cursor={}",
                    url::form_urlencoded::byte_serialize(c.as_bytes()).collect::<String>()
                ),
            };
            let before = k.metric(series);
            let r = cl.get(&url);
            assert_eq!(r.status, 200, "{url}: {}", r.body);
            let delta = k.metric(series) - before;
            assert!(delta > 0 && delta <= total_users, "{url} examined {delta}");
            let j = r.json();
            items.extend(j["items"].as_array().unwrap().clone());
            match j["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
        }
        items
    };
    let emails = |path: &str| -> Vec<String> {
        walk(path)
            .iter()
            .map(|i| i["primary_email"].as_str().unwrap_or("").to_string())
            .collect()
    };

    // user1 matches by email prefix: user1, user10..user19, user100..user199 (7 is renamed).
    let u1 = emails("/v1/users?q=user1&limit=50");
    assert_eq!(u1.len(), 1 + 10 + 100, "{u1:?}");
    assert!(u1.iter().all(|e| e.starts_with("user1")));
    // The exact address is one user.
    assert_eq!(
        emails("/v1/users?q=x@example.test&limit=50"),
        vec!["x@example.test".to_string()]
    );
    // A display-name substring, ASCII case-insensitive.
    assert_eq!(walk("/v1/users?q=kim&limit=50").len(), 12);
    assert_eq!(walk("/v1/users?q=Kim&limit=50").len(), 12);
    // The status filter narrows.
    let d = walk("/v1/users?q=user1&status=disabled&limit=50");
    assert_eq!(ids(&d).len(), 3, "11, 12 and 150");
    assert_eq!(walk("/v1/users?q=kim&status=disabled&limit=50").len(), 1);
    // An `@` prefix matches no address start.
    assert!(walk("/v1/users?q=%40example&limit=50").is_empty());
}

#[test]
fn s301_3_detail_shows_bounded_previews_totals_and_links() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let now = k.now_s();
    k.add_user("u_x", "x@example.test", "Ex");
    k.add_identity("u_x", "mock", "sub-7", "x@example.test");
    k.add_identity("u_x", "mock2", "sub-7b", "x2@example.test");
    for i in 0..4 {
        k.add_session(
            &format!("s_x{i}"),
            "u_x",
            now - 40 + i * 10,
            "203.0.113.9",
            Some("Mozilla/5.0 Alpha"),
            &["app.example.test", "other.example.org"],
            None,
            None,
        );
    }
    k.add_session(
        "s_xold1",
        "u_x",
        now - 500,
        "203.0.113.9",
        None,
        &["app.example.test"],
        Some((now - 100, "logout")),
        None,
    );
    k.add_session(
        "s_xold2",
        "u_x",
        now - 600,
        "203.0.113.9",
        None,
        &["app.example.test"],
        Some((now - 90, "admin")),
        None,
    );
    k.add_events(
        "x",
        80,
        "login.started",
        "info",
        Some("u_x"),
        None,
        None,
        now - 5,
    );
    let cl = k.client(&a);

    let r = cl.get("/v1/users/u_x");
    assert_eq!(r.status, 200, "{}", r.body);
    let j = r.json();
    assert_eq!(j["user"]["user_id"], "u_x");
    assert_eq!(j["user"]["primary_email"], "x@example.test");
    let idents = j["identities"].as_array().unwrap();
    assert_eq!(idents.len(), 2);
    for i in idents {
        for f in [
            "provider_id",
            "subject",
            "email",
            "email_verified",
            "name",
            "first_seen_at",
            "last_seen_at",
        ] {
            assert!(i.get(f).is_some(), "{f}");
        }
    }
    assert!(
        !r.body.contains("raw_claims") && !r.body.contains("secret_claim"),
        "never raw_claims"
    );
    let live = j["sessions_live"].as_array().unwrap();
    assert_eq!(live.len(), 4);
    assert_eq!(j["sessions_live_total"], 4);
    let created: Vec<i64> = live
        .iter()
        .map(|s| s["created_at"].as_i64().unwrap())
        .collect();
    assert!(
        created.windows(2).all(|w| w[0] >= w[1]),
        "newest created first"
    );
    for s in live {
        assert_eq!(s["bound_ip"], "203.0.113.9");
        assert_eq!(s["ua_prefix"], "Mozilla/5.0 Alpha");
        assert_eq!(s["hosts"].as_array().unwrap().len(), 2);
        for f in ["aal", "auth_time", "last_seen_at"] {
            assert!(s.get(f).is_some(), "{f}");
        }
    }
    let ended = j["sessions_terminated"].as_array().unwrap();
    assert_eq!(ended.len(), 2);
    assert!(ended.iter().all(|s| s["terminated_reason"].is_string()));
    assert_eq!(
        j["events"].as_array().unwrap().len(),
        50,
        "the 50 most recent of 80"
    );
    assert!(j["grant"].is_null());
    assert_eq!(j["sessions_url"], "/sessions?user_id=u_x");
    assert_eq!(j["events_url"], "/events?user_id=u_x");

    // The page, for an administrator: forms and links.
    let p = cl.get("/users/u_x");
    assert_eq!(p.status, 200);
    assert!(p.body.contains("/users/u_x/disable"), "disable form");
    assert!(
        p.body.contains("/users/u_x/sessions/terminate"),
        "terminate-all form"
    );
    assert!(p.body.contains("/sessions?user_id=u_x") && p.body.contains("/events?user_id=u_x"));
    assert!(p.body.contains("name=\"csrf\""));
    // A read-only administrator sees the page without any form.
    let v = k.admin("sub-v", AdminRole::Viewer);
    let pv = k.client(&v).get("/users/u_x");
    assert_eq!(pv.status, 200);
    assert!(
        !pv.body.contains("<form"),
        "no state-changing form for a viewer"
    );

    // A user with 500 live sessions: previews stay bounded.
    k.add_user("u_many", "many@example.test", "Many");
    for (i, p) in ["mock", "mock", "mock2"].iter().enumerate() {
        k.add_identity("u_many", p, &format!("many-{i}"), "many@example.test");
    }
    k.h.hooks.bulk_sessions("u_many", 500);
    let t = std::time::Instant::now();
    let r = cl.get("/v1/users/u_many");
    assert_eq!(r.status, 200);
    assert!(
        t.elapsed() < std::time::Duration::from_secs(2),
        "within the budget"
    );
    assert!(r.body.len() < 64 * 1024, "{} bytes", r.body.len());
    let j = r.json();
    assert_eq!(j["sessions_live"].as_array().unwrap().len(), 20);
    assert_eq!(j["sessions_live_total"], 500);
    assert_eq!(j["identities"].as_array().unwrap().len(), 3);
    // The listing behind sessions_url pages through all 500 in 200s.
    let all = cl.walk_rows("/v1/sessions?user_id=u_many&limit=200", 500);
    assert_eq!(all.len(), 500);
}

/// The session ids of a user, in the table.
fn live_sessions_of(k: &Console, user: &str) -> i64 {
    k.count(&format!(
        "SELECT COUNT(*) FROM sessions WHERE user_id = '{user}' AND terminated_at IS NULL"
    ))
}

fn user_row(k: &Console, user: &str) -> (String, i64) {
    k.sql()
        .query_row(
            "SELECT status, authz_version FROM users WHERE user_id = ?1",
            [user],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// `u_x` with four live sessions (returns their app-host handles), `authz_version = 3`.
fn seed_ux(k: &Console) -> Vec<String> {
    let now = k.now_s();
    k.add_user("u_x", "x@example.test", "Ex");
    k.add_identity("u_x", "mock", "sub-7", "x@example.test");
    k.sql()
        .execute(
            "UPDATE users SET authz_version = 3 WHERE user_id = 'u_x'",
            [],
        )
        .unwrap();
    let mut handles = Vec::new();
    for i in 0..4 {
        let hs = k.add_session(
            &format!("s_x{i}"),
            "u_x",
            now - 40 + i * 10,
            kit::CLIENT_IP,
            None,
            &["app.example.test", "other.example.org"],
            None,
            None,
        );
        handles.push(hs[0].clone());
    }
    handles
}

#[test]
fn s301_4_disable_ends_sessions_with_audit_in_one_transaction() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let handles = seed_ux(&k);
    // An outstanding handoff code of s_x0.
    {
        let now = k.now_s();
        k.sql()
            .execute(
                "INSERT INTO handoff_codes (code_sha256, session_id, host, return_target, return_path, client_ip, bind_sha256, issued_aal, cred_gen, created_at, expires_at) VALUES (zeroblob(32), 's_x0', 'other.example.org', 'https://other.example.org/', '/', '192.0.2.10', zeroblob(32), 1, 1, ?1, ?1 + 60)",
                [now],
            )
            .unwrap();
    }
    let cl = k.client(&a);
    let r = cl.post_json("/v1/users/u_x/disable", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"changed": true, "sessions_terminated": 4}));
    let now = k.now_s();
    assert_eq!(user_row(&k, "u_x"), ("disabled".to_string(), 4));
    assert_eq!(
        k.count("SELECT updated_at FROM users WHERE user_id = 'u_x'"),
        now,
        "updated_at = now"
    );
    assert_eq!(live_sessions_of(&k, "u_x"), 0);
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE user_id = 'u_x' AND terminated_reason = 'user_disabled' AND terminated_at = {now}"
        )),
        4
    );
    assert_eq!(
        k.count("SELECT COUNT(*) FROM sessions WHERE user_id = 'u_x' AND cred_gen = 2"),
        4,
        "cred_gen incremented"
    );
    assert_eq!(k.count("SELECT COUNT(*) FROM session_handles WHERE session_id LIKE 's_x%' AND revoked_at IS NULL"), 0);
    assert_eq!(
        k.count("SELECT COUNT(*) FROM handoff_codes WHERE consumed_at IS NULL"),
        0,
        "codes consumed"
    );

    // The events of one transaction.
    let dis = k.events("admin.user_disable");
    assert_eq!(dis.len(), 1);
    assert_eq!(dis[0]["user_id"], "u_x");
    assert_eq!(dis[0]["attrs"]["actor"], a.user_id.as_str());
    assert!(
        dis[0]["attrs"]["actor_session"]
            .as_str()
            .unwrap()
            .starts_with("s_")
    );
    assert_eq!(dis[0]["attrs"]["count"], 4);
    let term: Vec<_> = k
        .events("session.terminated")
        .into_iter()
        .filter(|e| e["user_id"] == "u_x")
        .collect();
    assert_eq!(term.len(), 4);
    assert!(term.iter().all(|e| e["reason"] == "user_disabled"));

    // A verify with a former handle on the application host is refused and the cookie cleared.
    let v = k.h.verify(
        VerifyRequest::document("https://app.example.test/x")
            .ip(kit::CLIENT_IP)
            .cookie("__Host-hopae", &handles[0]),
    );
    assert_eq!(v.status, 302, "{v:?}");
    assert!(
        v.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-hopae=") && c.contains("Max-Age=0")),
        "cookie cleared: {:?}",
        v.set_cookies()
    );
    // A new login by u_x is refused at the callback.
    let (cb, redeem) = k.login_raw("sub-7", "x@example.test", "Ex");
    assert!(redeem.is_none(), "{cb:?}");
    assert!(
        k.events("login.failed")
            .iter()
            .any(|e| e["reason"] == "user_disabled")
    );

    // The crash point before the commit leaves nothing changed and no event.
    let mut k2 = Console::new();
    let a2 = k2.admin("sub-a", AdminRole::Admin);
    seed_ux(&k2);
    k2.h.hooks.crash_at("after_admin_status_write");
    let admin = k2.h.admin.unwrap();
    let req = RawReq::new("POST", "/v1/users/u_x/disable", &k2.h.console_host())
        .header("x-forwarded-host", &k2.h.console_host())
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", kit::CLIENT_IP)
        .header("cookie", &format!("__Host-hopae={}", a2.handle))
        .header("content-type", "application/json")
        .header("x-hopae-admin-request", "1");
    let mut req = req;
    req.body = b"{}".to_vec();
    let _ = hopae_try(admin, req);
    k2.h.wait_exit(std::time::Duration::from_secs(10))
        .expect("the process crashed");
    k2.h.restart();
    assert_eq!(user_row(&k2, "u_x"), ("active".to_string(), 3));
    assert_eq!(live_sessions_of(&k2, "u_x"), 4);
    assert!(k2.events("admin.user_disable").is_empty());
}

fn hopae_try(addr: std::net::SocketAddr, req: RawReq) -> std::io::Result<Response> {
    crate::support::client::try_send(addr, req)
}

#[test]
fn s301_5_enable_restores_sign_in_and_revives_nothing() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_ux(&k);
    let cl = k.client(&a);
    assert_eq!(cl.post_json("/v1/users/u_x/disable", json!({})).status, 200);
    let r = cl.post_json("/v1/users/u_x/enable", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json(), json!({"changed": true}));
    assert_eq!(user_row(&k, "u_x"), ("active".to_string(), 5));
    assert_eq!(live_sessions_of(&k, "u_x"), 0, "nothing revived");
    assert_eq!(k.count("SELECT COUNT(*) FROM session_handles WHERE session_id LIKE 's_x%' AND revoked_at IS NULL"), 0);
    let en = k.events("admin.user_enable");
    assert_eq!(en.len(), 1);
    assert_eq!(en[0]["user_id"], "u_x");
    assert_eq!(en[0]["attrs"]["actor"], a.user_id.as_str());
    // u_x can sign in again and gets a new session.
    let w = k.login("sub-7", "x@example.test", "Ex");
    assert_eq!(w.user_id, "u_x");
    assert_eq!(live_sessions_of(&k, "u_x"), 1);
}

#[test]
fn s301_6_changing_nothing_writes_nothing() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_ux(&k);
    let cl = k.client(&a);
    assert_eq!(cl.post_json("/v1/users/u_x/disable", json!({})).status, 200);
    let events_before = k.count("SELECT COUNT(*) FROM events");
    let r = cl.post_json("/v1/users/u_x/disable", json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({"changed": false, "sessions_terminated": 0})
    );
    assert_eq!(user_row(&k, "u_x").1, 4, "authz_version unchanged");
    assert_eq!(
        k.count("SELECT COUNT(*) FROM events"),
        events_before,
        "no event"
    );
    assert_eq!(cl.post_json("/v1/users/u_x/enable", json!({})).status, 200);
    let events_before = k.count("SELECT COUNT(*) FROM events");
    let r = cl.post_json("/v1/users/u_x/enable", json!({}));
    assert_eq!(r.json(), json!({"changed": false}));
    assert_eq!(user_row(&k, "u_x").1, 5);
    assert_eq!(k.count("SELECT COUNT(*) FROM events"), events_before);
    // Terminating every session of a user without live sessions is a no-op too.
    let r = cl.post_json("/v1/users/u_x/sessions/terminate", json!({}));
    assert_eq!(r.json(), json!({"terminated": 0}));
    assert_eq!(k.count("SELECT COUNT(*) FROM events"), events_before);
}

#[test]
fn s301_7_disabled_administrator_loses_the_console() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let b = k.admin("sub-b", AdminRole::Admin);
    assert_eq!(k.client(&b).get("/v1/users?limit=1").status, 200);
    let r = k
        .client(&a)
        .post_json(&format!("/v1/users/{}/disable", b.user_id), json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    let r = k.client(&b).get("/v1/users?limit=1");
    assert_eq!(r.status, 403);
    assert_eq!(code(&r), "login_required");
    // b's console session ended with reason user_disabled; the grant row is untouched.
    assert_eq!(
        k.count(&format!(
            "SELECT COUNT(*) FROM sessions WHERE user_id = '{}' AND terminated_reason = 'user_disabled'",
            b.user_id
        )),
        1
    );
    let grants = k.h.hooks.grants();
    let gb = grants
        .iter()
        .find(|g| g["user_id"] == b.user_id.as_str())
        .expect("b's grant");
    assert!(gb["revoked_at"].is_null(), "grant untouched");
    let ev = k.events("admin.user_disable");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["user_id"], b.user_id.as_str());
    assert_eq!(ev[0]["attrs"]["actor"], a.user_id.as_str());
}

#[test]
fn s301_a1_replayed_disable_is_noop_and_token_rules() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    seed_ux(&k);
    let cl = k.client(&a);
    // The JSON replay.
    assert_eq!(
        cl.post_json("/v1/users/u_x/disable", json!({})).json()["changed"],
        true
    );
    let events = k.count("SELECT COUNT(*) FROM events");
    let r = cl.post_json("/v1/users/u_x/disable", json!({}));
    assert_eq!(r.json()["changed"], false);
    assert_eq!(k.count("SELECT COUNT(*) FROM events"), events);
    // The form replay: the same token twice, both accepted, the second a no-op.
    k.sql()
        .execute(
            "UPDATE users SET status = 'active' WHERE user_id = 'u_x'",
            [],
        )
        .unwrap();
    let page = cl.get("/users/u_x");
    let token = AdminClient::csrf_from_page(&page.body).expect("a csrf field");
    let origin = k.origin();
    let first = cl.post_form(
        "/users/u_x/disable",
        &[("csrf", &token), ("back", "user"), ("user_id", "u_x")],
        Some(&origin),
    );
    assert_eq!(first.status, 303, "{first:?}");
    assert_eq!(first.location(), Some("/users/u_x"));
    let version = user_row(&k, "u_x").1;
    let events = k.count("SELECT COUNT(*) FROM events");
    let second = cl.post_form(
        "/users/u_x/disable",
        &[("csrf", &token), ("back", "user"), ("user_id", "u_x")],
        Some(&origin),
    );
    assert_eq!(second.status, 303, "{second:?}");
    assert_eq!(user_row(&k, "u_x").1, version, "authz_version unchanged");
    assert_eq!(k.count("SELECT COUNT(*) FROM events"), events, "no event");
    assert_eq!(live_sessions_of(&k, "u_x"), 0);
}

#[test]
fn s301_a2_malformed_ids_and_parameters_rejected() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let cl = k.client(&a);
    let bad = |path: &str, status: u16, want: &str| {
        let r = cl.get(path);
        assert_eq!(
            (r.status, code(&r).as_str()),
            (status, want),
            "{path}: {}",
            r.body
        );
        assert!(!r.body.contains("OR"), "no echo of the input");
    };
    bad("/v1/users/u_doesnotexist", 404, "not_found");
    bad("/v1/users/u_x%27%20OR%201=1", 400, "invalid_id");
    bad(
        &format!("/v1/users/u_{}", "a".repeat(298)),
        400,
        "invalid_id",
    );
    bad("/v1/users?limit=0", 400, "invalid_filter");
    bad("/v1/users?limit=201", 400, "invalid_filter");
    bad("/v1/users?limit=abc", 400, "invalid_filter");
    bad("/v1/users?status=banned", 400, "invalid_filter");
    bad("/v1/users?cursor=AAAA", 400, "invalid_cursor");
    bad(
        &format!("/v1/users?q={}", "a".repeat(129)),
        400,
        "invalid_filter",
    );
    bad("/v1/users?q=%00", 400, "invalid_filter");
    // A session id is not a user id; the store is not touched.
    let before = k.h.hooks.counters()["store_calls"].to_string();
    let r = cl.post_json("/v1/users/s_x/disable", json!({}));
    assert_eq!((r.status, code(&r).as_str()), (400, "invalid_id"));
    let _ = before;
    // SQL wildcards are matched literally: nothing starts with or contains `%%`.
    let r = cl.get("/v1/users?q=%25%25");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 0);
    let r = cl.get("/v1/users?q=_");
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json()["items"].as_array().unwrap().len(),
        0,
        "`_` is not a wildcard"
    );
}

#[test]
fn s301_a3_concurrent_admins_and_in_flight_login() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let b = k.admin("sub-b", AdminRole::Admin);
    seed_ux(&k);
    k.h.hooks.hold("admin_status");
    let (ra, rb) = std::thread::scope(|s| {
        let first = s.spawn(|| k.client(&a).post_json("/v1/users/u_x/disable", json!({})));
        std::thread::sleep(std::time::Duration::from_millis(500));
        let second = s.spawn(|| k.client(&b).post_json("/v1/users/u_x/disable", json!({})));
        std::thread::sleep(std::time::Duration::from_millis(500));
        k.h.hooks.release("admin_status");
        (first.join().unwrap(), second.join().unwrap())
    });
    let changed = [
        ra.json()["changed"].as_bool(),
        rb.json()["changed"].as_bool(),
    ];
    assert_eq!(
        changed.iter().filter(|c| **c == Some(true)).count(),
        1,
        "{ra:?} {rb:?}"
    );
    assert_eq!(changed.iter().filter(|c| **c == Some(false)).count(), 1);
    assert_eq!(k.events("admin.user_disable").len(), 1);
    assert_eq!(
        user_row(&k, "u_x"),
        ("disabled".to_string(), 4),
        "moved exactly once"
    );

    // A login of the user in flight (held before its commit) while a disable commits.
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.add_user("u_x", "x@example.test", "Ex");
    k.add_identity("u_x", "mock", "sub-7", "x@example.test");
    k.h.hooks.hold("login_commit");
    let (pending, disabled) = std::thread::scope(|s| {
        let login = s.spawn(|| k.begin_login("sub-7", "x@example.test", "Ex"));
        std::thread::sleep(std::time::Duration::from_millis(700));
        let dis = s.spawn(|| k.client(&a).post_json("/v1/users/u_x/disable", json!({})));
        std::thread::sleep(std::time::Duration::from_millis(700));
        k.h.hooks.release("login_commit");
        (login.join().unwrap(), dis.join().unwrap())
    });
    assert_eq!(disabled.status, 200, "{}", disabled.body);
    assert_eq!(user_row(&k, "u_x").0, "disabled");
    // Whatever the order, u_x ends with no usable handle.
    if let Ok((url, bind)) = pending {
        let r = k.redeem(&url, &bind);
        assert!(
            !r.set_cookies()
                .iter()
                .any(|c| c.starts_with("__Host-hopae=") && !c.contains("Max-Age=0")),
            "no usable handle: {r:?}"
        );
    }
    assert_eq!(live_sessions_of(&k, "u_x"), 0);
    assert_eq!(k.count("SELECT COUNT(*) FROM session_handles h JOIN sessions s ON s.session_id = h.session_id WHERE s.user_id = 'u_x' AND h.revoked_at IS NULL"), 0);
    assert_eq!(user_row(&k, "u_x").1, 2, "authz_version moved exactly once");
}

#[test]
fn s301_a4_listing_and_search_examine_bounded_window() {
    // The sparse search over 100,000 users.
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_users(100_000);
    let cl = k.client(&a);
    let series = "hopae_admin_rows_examined_total{list=\"users\"}";
    let before = k.metric(series);
    let r = cl.get("/v1/users?q=zzqx").json();
    assert_eq!(r["items"].as_array().unwrap().len(), 0);
    assert!(r["next_cursor"].is_string(), "an empty page with a cursor");
    assert_eq!(
        k.metric(series) - before,
        10_000,
        "exactly one window examined"
    );
    // The walk ends; every request examines at most one window.
    let mut pages = 1;
    let mut cursor = r["next_cursor"].as_str().map(str::to_string);
    while let Some(c) = cursor {
        let enc: String = url::form_urlencoded::byte_serialize(c.as_bytes()).collect();
        let before = k.metric(series);
        let r = cl.get(&format!("/v1/users?q=zzqx&cursor={enc}")).json();
        assert!(k.metric(series) - before <= 10_000);
        cursor = r["next_cursor"].as_str().map(str::to_string);
        pages += 1;
        assert!(pages <= 12, "the walk must end");
    }
    assert!(pages >= 10, "{pages} pages for 100,001 users");
    // The plans: one range scan, and a row-value seek on a cursor page.
    let e = k.h.hooks.explain("users", true);
    assert!(e["plan"].to_string().contains("users_created_id"));
    let deep = k.h.hooks.explain(
        &format!("users&cursor={}:u_blk000050000", k.h.hooks.now_ms()),
        true,
    );
    assert!(
        deep["plan"]
            .to_string()
            .contains("(created_at,user_id)<(?,?)"),
        "{deep}"
    );
    let shallow = k.h.hooks.explain(
        &format!("users&cursor={}:u_blk000099000", k.h.hooks.now_ms()),
        true,
    );
    let (s1, s2) = (
        shallow["vm_step"].as_i64().unwrap_or(0),
        deep["vm_step"].as_i64().unwrap_or(0),
    );
    assert!(s1 > 0 && s2 > 0, "{shallow} {deep}");
    let ratio = s2 as f64 / s1 as f64;
    assert!(
        (0.9..=1.1).contains(&ratio),
        "deep cursor costs the same: {s1} vs {s2}"
    );
}

#[test]
fn s301_a4_budget_interrupts_and_rolls_back() {
    let k = Console::with(json!({"admin": {"query_budget_ms": 100}}));
    let a = k.admin("sub-a", AdminRole::Admin);
    k.h.hooks.bulk_users(20_000);
    let cl = k.client(&a);
    // A scan that cannot finish: interrupted inside the store.
    k.h.hooks.slow_scan(1);
    let before = k.metric("hopae_store_interrupts_total");
    let t = std::time::Instant::now();
    let r = cl.get("/v1/users?q=zzqx");
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    assert!(t.elapsed() < std::time::Duration::from_millis(1500));
    assert!(
        k.metric("hopae_store_interrupts_total") > before,
        "interrupted, not merely abandoned"
    );
    k.h.hooks.slow_scan_off();
    // A mutation under the same budget: interrupted between statements, rolled back.
    k.add_user("u_big", "big@example.test", "Big");
    k.h.hooks.bulk_sessions("u_big", 5000);
    k.h.hooks.slow_scan(1);
    let r = cl.post_json("/v1/users/u_big/disable", json!({}));
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    k.h.hooks.slow_scan_off();
    assert_eq!(user_row(&k, "u_big").0, "active");
    assert_eq!(live_sessions_of(&k, "u_big"), 5000);
    assert!(k.events("admin.user_disable").is_empty());
    // The writer is free for the next job.
    assert_eq!(cl.get("/v1/users?limit=1").status, 200);
    // Lock contention: the budget bounds the wait for the lock.
    k.add_user("u_x", "x@example.test", "Ex");
    k.h.hooks.hold_write_lock(3000);
    let t = std::time::Instant::now();
    let r = cl.post_json("/v1/users/u_x/disable", json!({}));
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    assert!(
        t.elapsed() < std::time::Duration::from_millis(1500),
        "bounded by the budget: {:?}",
        t.elapsed()
    );
    std::thread::sleep(std::time::Duration::from_millis(3200));
    assert_eq!(user_row(&k, "u_x").0, "active", "nothing committed late");
    assert!(k.events("admin.user_disable").is_empty());
}

#[test]
fn s301_a4_refusals_bound_their_required_audit_writes_by_the_budget() {
    // A refusal's own `admin.denied` / `csrf.rejected` write waits for the
    // same lock a mutation does; under contention it is bounded by the budget
    // (the refusal stands, the audit write is abandoned and rolled back).
    let k = Console::with(json!({"admin": {"query_budget_ms": 100}}));
    let a = k.admin("sub-a", AdminRole::Admin);
    let v = k.admin("sub-v", AdminRole::Viewer);
    let n = k.login("sub-n", "sub-n@admin.test", "Nobody");
    k.add_user("u_x", "x@example.test", "Ex");
    let bounded = |what: &str, expect: (u16, &str), run: &dyn Fn() -> Response| {
        k.h.hooks.hold_write_lock(4000);
        let t = std::time::Instant::now();
        let r = run();
        let took = t.elapsed();
        assert_eq!((r.status, code(&r).as_str()), expect, "{what}: {}", r.body);
        assert!(
            took < std::time::Duration::from_millis(1500),
            "{what}: the refusal's audit write waited {took:?} for the lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(4300));
    };
    bounded("csrf_rejected", (403, "csrf_rejected"), &|| {
        k.client(&a).post_json_raw(
            "/v1/users/u_x/disable",
            &[("content-type", "application/json")],
            b"{}",
        )
    });
    assert!(
        k.events("csrf.rejected").is_empty(),
        "nothing is recorded late"
    );
    bounded("role_insufficient", (403, "role_insufficient"), &|| {
        k.client(&v).post_json("/v1/users/u_x/disable", json!({}))
    });
    bounded("not_admin", (403, "not_admin"), &|| {
        k.client(&n).get("/v1/users")
    });
    assert!(
        k.events("admin.denied").is_empty(),
        "nothing is recorded late: {:?}",
        k.events("admin.denied")
    );
    // Without contention the same refusals are recorded.
    let r = k.client(&n).get("/v1/users");
    assert_eq!(r.status, 403);
    assert_eq!(k.events("admin.denied").len(), 1);
}

#[test]
fn s301_a4_the_verify_budget_cannot_extend_the_admin_budget() {
    // The engine runs the handle reads of the console's authentication under
    // its own (gateway) budget; the console's smaller budget must still win.
    let k = Console::with(
        json!({"admin": {"query_budget_ms": 100}, "gateway": {"verify_budget_ms": 10000}}),
    );
    let a = k.admin("sub-a", AdminRole::Admin);
    assert_eq!(k.client(&a).get("/v1/me").status, 200);
    let denied_before = k.events("admin.denied").len();
    k.h.hooks.stall(1500);
    let t = std::time::Instant::now();
    let r = k.client(&a).get("/v1/me");
    let took = t.elapsed();
    k.h.hooks.stall_off();
    assert_eq!(
        (r.status, code(&r).as_str()),
        (503, "store_unavailable"),
        "{}",
        r.body
    );
    assert!(
        took < std::time::Duration::from_millis(900),
        "answered after {took:?}, not within the admin budget"
    );
    // Nothing lands late: no refusal record, and the console works again.
    std::thread::sleep(std::time::Duration::from_millis(2000));
    assert_eq!(k.events("admin.denied").len(), denied_before);
    assert_eq!(k.client(&a).get("/v1/me").status, 200);
}

#[test]
fn s301_a4_terminate_of_five_thousand_sessions_with_a_large_budget() {
    let k = Console::with(json!({"admin": {"query_budget_ms": 30000}}));
    let a = k.admin("sub-a", AdminRole::Admin);
    k.add_user("u_big", "big@example.test", "Big");
    k.h.hooks.bulk_sessions("u_big", 5000);
    let r = k.client(&a).post_json("/v1/users/u_big/disable", json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["sessions_terminated"], 5000);
}

#[test]
fn s301_a5_no_self_disable_and_viewer_cannot_disable() {
    let k = Console::new();
    let a = k.admin("sub-a", AdminRole::Admin);
    let v = k.admin("sub-v", AdminRole::Viewer);
    seed_ux(&k);
    let self_series = "hopae_admin_denied_total{reason=\"self_target\"}";
    let s0 = k.metric(self_series);
    let r = k
        .client(&a)
        .post_json(&format!("/v1/users/{}/disable", a.user_id), json!({}));
    assert_eq!((r.status, code(&r).as_str()), (403, "self_target"));
    let r = k.client(&v).post_json("/v1/users/u_x/disable", json!({}));
    assert_eq!((r.status, code(&r).as_str()), (403, "role_insufficient"));
    // The HTML form of the self-target.
    let page = k.client(&a).get("/users/u_x");
    let token = AdminClient::csrf_from_page(&page.body).expect("csrf");
    let r = k.client(&a).post_form(
        &format!("/users/{}/disable", a.user_id),
        &[("csrf", &token)],
        Some(&k.origin()),
    );
    // A form answers with the denial page, which names the code.
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(r.body.contains("self_target"), "{}", r.body);
    assert_eq!(
        k.metric(self_series),
        s0 + 2,
        "self_target is counted once per refusal"
    );
    // The viewer's page offers no form at all.
    let pv = k.client(&v).get("/users/u_x");
    assert!(!pv.body.contains("/disable"), "no action for a viewer");
    // Both refusals are recorded; nothing changed.
    let denied = k.events("admin.denied");
    let reasons: Vec<_> = denied
        .iter()
        .map(|e| e["reason"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        reasons.iter().filter(|r| *r == "self_target").count(),
        2,
        "{reasons:?}"
    );
    assert_eq!(
        reasons.iter().filter(|r| *r == "role_insufficient").count(),
        1
    );
    assert_eq!(user_row(&k, "u_x"), ("active".to_string(), 3));
    assert_eq!(user_row(&k, &a.user_id).0, "active");
    // Another administrator may disable `u_a` (301-7 covers the consequences).
    let b = k.admin("sub-b", AdminRole::Admin);
    assert_eq!(
        k.client(&b)
            .post_json(&format!("/v1/users/{}/disable", a.user_id), json!({}))
            .status,
        200
    );
}

#[test]
fn s301_a6_directory_enumeration_needs_grant_and_is_bounded() {
    let k = Console::new();
    let _a = k.admin("sub-a", AdminRole::Admin);
    let n = k.login("sub-n", "n@example.test", "No grant");
    let before = k.h.hooks.counters()["store_calls"].clone();
    let called = |c: &Value, m: &str| c[m].as_u64().unwrap_or(0);
    let r = k.client(&n).get("/v1/users?q=a");
    assert_eq!((r.status, code(&r).as_str()), (403, "not_admin"));
    let r = k.client(&n).get("/users?q=a");
    assert_eq!(r.status, 403);
    let r = k.h.admin_client().get("/v1/users?q=a");
    assert_eq!((r.status, code(&r).as_str()), (403, "login_required"));
    let r = k.h.admin_client().get("/users?q=a");
    assert_eq!(r.status, 403);
    let after = k.h.hooks.counters()["store_calls"].clone();
    for m in ["list_users", "user_detail"] {
        assert_eq!(called(&before, m), called(&after, m), "{m} not executed");
    }
    // Emails never appear in the URLs the console emits.
    let ok = k.client(&_a).get("/users");
    assert!(!ok.body.contains("href=\"/users/n@") && !ok.body.contains("href=\"/users?q="));
    for l in ok.body.split("href=\"").skip(1) {
        let url = l.split('"').next().unwrap();
        assert!(!url.contains('@'), "an email in {url}");
    }
}
