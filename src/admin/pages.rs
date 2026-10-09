//! The console's HTML: askama templates under `templates/admin/`, English and
//! Korean through the portal's string tables (`admin.*` keys).
//!
//! Every page struct carries a [`Chrome`] named `c` (strings, request id,
//! navigation, the signed-in administrator): `templates/admin/layout.html`
//! reads only that, so a page of another module extends the layout by adding
//! `c: &'a Chrome<'a>` to its struct. Everything askama prints is escaped, and
//! no page contains or loads a script.

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;

use super::{AdminState, Principal, ReqInfo};
use crate::portal::i18n::{Strings, strings};
use crate::store::AdminRole;

/// The stylesheet served at `/assets/admin.css`.
pub const STYLESHEET: &str = include_str!("../../templates/static/admin.css");

/// What the layout needs: strings, the request id, the navigation and who is
/// signed in.
pub struct Chrome<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    /// The active navigation entry: `status`, `users`, `sessions`, `events`.
    pub active: &'static str,
    /// Navigation and the sign-out link (off on denial pages).
    pub show_nav: bool,
    /// `email (role)`, or the user id without an address.
    pub who: String,
    /// The application-host logout entry point of the console host.
    pub logout_url: String,
}

impl<'a> Chrome<'a> {
    /// The layout for a signed-in administrator.
    pub fn signed_in(
        st: &AdminState,
        req: &'a ReqInfo,
        p: &Principal,
        active: &'static str,
    ) -> Chrome<'a> {
        let t = strings(req.lang);
        let role = match p.role {
            AdminRole::Admin => t.get("admin.common.role_admin"),
            AdminRole::Viewer => t.get("admin.common.role_viewer"),
        };
        let name = p
            .email
            .as_ref()
            .map_or_else(|| p.user_id.to_string(), ToString::to_string);
        Chrome {
            t,
            request_id: &req.rid,
            active,
            show_nav: true,
            who: format!("{name} ({role})"),
            logout_url: logout_url(st),
        }
    }

    /// The bare layout of a denial page: no navigation, nothing of the console.
    pub fn bare(req: &'a ReqInfo) -> Chrome<'a> {
        Chrome {
            t: strings(req.lang),
            request_id: &req.rid,
            active: "",
            show_nav: false,
            who: String::new(),
            logout_url: String::new(),
        }
    }
}

/// `https://<console>/_hopae/logout`.
pub fn logout_url(st: &AdminState) -> String {
    format!("{}/_hopae/logout", console_origin(st))
}

/// `https://<console>` as browsers write the origin.
pub fn console_origin(st: &AdminState) -> String {
    st.cfg.origin.ascii_serialization()
}

/// The console's front door: where a refused browser is sent to sign in.
pub fn console_url(st: &AdminState) -> String {
    format!("{}/", console_origin(st))
}

#[derive(Template)]
#[template(path = "admin/denied.html")]
pub struct Denied<'a> {
    pub c: &'a Chrome<'a>,
    /// The machine-readable code, shown beneath the text.
    pub code: &'a str,
    pub title_key: &'static str,
    pub body_key: &'static str,
    pub user_id: Option<&'a str>,
    pub email: Option<&'a str>,
    pub login_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "admin/error.html")]
pub struct ErrorPage<'a> {
    pub c: &'a Chrome<'a>,
    pub code: &'a str,
    pub title_key: &'static str,
    pub body_key: &'static str,
}

/// Title and body keys of an error code (`admin.denied.<code>.title|body`).
pub fn keys(code: &str) -> (&'static str, &'static str) {
    macro_rules! codes {
        ($($c:literal),+ $(,)?) => {
            match code {
                $($c => (
                    concat!("admin.denied.", $c, ".title"),
                    concat!("admin.denied.", $c, ".body"),
                ),)+
                _ => ("admin.denied.generic.title", "admin.denied.generic.body"),
            }
        };
    }
    codes!(
        "untrusted_peer",
        "login_required",
        "auth_too_old",
        "not_admin",
        "role_insufficient",
        "aal_insufficient",
        "self_target",
        "csrf_rejected",
        "actor_revoked",
        "not_found",
        "method_not_allowed",
        "payload_too_large",
        "header_too_large",
        "invalid_cursor",
        "invalid_filter",
        "invalid_id",
        "store_unavailable",
        "overloaded",
        "not_implemented",
    )
}

/// An HTML response with the given status.
pub fn html(status: StatusCode, body: String) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r
}

/// Render `page` with `status`; a rendering failure is a bare `503`.
pub fn render<T: Template>(status: StatusCode, page: &T) -> Response {
    match page.render() {
        Ok(body) => html(status, body),
        Err(_) => html(StatusCode::SERVICE_UNAVAILABLE, "unavailable".to_string()),
    }
}

/// The denial or error page for `code`. `extra` carries what a denial page
/// may show: the console link and, for `not_admin`, the user.
pub struct Extra<'a> {
    pub user_id: Option<&'a str>,
    pub email: Option<&'a str>,
    pub login_url: Option<&'a str>,
}

impl Extra<'_> {
    pub const NONE: Extra<'static> = Extra {
        user_id: None,
        email: None,
        login_url: None,
    };
}

pub fn denied_page(req: &ReqInfo, status: StatusCode, code: &str, extra: &Extra<'_>) -> Response {
    let c = Chrome::bare(req);
    let (title_key, body_key) = keys(code);
    render(
        status,
        &Denied {
            c: &c,
            code,
            title_key,
            body_key,
            user_id: extra.user_id,
            email: extra.email,
            login_url: extra.login_url,
        },
    )
}

/// An error page inside the layout of a signed-in administrator.
pub fn error_page(
    st: &AdminState,
    req: &ReqInfo,
    principal: &Principal,
    status: StatusCode,
    code: &str,
) -> Response {
    let c = Chrome::signed_in(st, req, principal, "");
    let (title_key, body_key) = keys(code);
    render(
        status,
        &ErrorPage {
            c: &c,
            code,
            title_key,
            body_key,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::i18n::Lang;

    fn used_keys() -> std::collections::BTreeSet<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/admin");
        let mut used = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "html") {
                let text = std::fs::read_to_string(&p).unwrap();
                for call in ["t.get(\"", "t.fmt(\""] {
                    let mut rest = text.as_str();
                    while let Some(i) = rest.find(call) {
                        rest = &rest[i + call.len()..];
                        let end = rest.find('"').unwrap();
                        used.insert(rest[..end].to_string());
                    }
                }
            }
        }
        used
    }

    #[test]
    fn every_key_an_admin_template_uses_exists_in_both_languages() {
        let used = used_keys();
        assert!(used.len() > 20, "{used:?}");
        for k in &used {
            assert!(strings(Lang::En).has(k), "en.toml lacks {k}");
            assert!(strings(Lang::Ko).has(k), "ko.toml lacks {k}");
        }
    }

    #[test]
    fn every_denial_code_has_text_in_both_languages() {
        for code in [
            "untrusted_peer",
            "login_required",
            "auth_too_old",
            "not_admin",
            "role_insufficient",
            "aal_insufficient",
            "self_target",
            "csrf_rejected",
            "actor_revoked",
            "not_found",
            "method_not_allowed",
            "payload_too_large",
            "header_too_large",
            "invalid_cursor",
            "invalid_filter",
            "invalid_id",
            "store_unavailable",
            "overloaded",
            "not_implemented",
        ] {
            let (t, b) = keys(code);
            assert!(!t.contains("generic"), "{code} has no keys");
            for lang in [Lang::En, Lang::Ko] {
                assert!(strings(lang).has(t) && strings(lang).has(b), "{code}");
            }
        }
    }

    #[test]
    fn the_stylesheet_loads_nothing_remote() {
        assert!(!STYLESHEET.contains("url(") && !STYLESHEET.contains("@import"));
    }
}
