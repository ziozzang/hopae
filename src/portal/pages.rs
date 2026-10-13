//! HTML pages (askama templates under `templates/`), English and Korean.
//!
//! No page runs script or carries inline style: the content security policy
//! allows neither. Every page shows the per-request id and no reason code, so
//! failure pages are identical for every cause of the same kind.

use askama::Template;

use super::i18n::Strings;
use super::ports::{FailKind, ProviderChoice};

/// The error pages, one per status the portal renders itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorPage {
    Expired,
    Failed,
    Forbidden,
    NotFound,
    BadRequest,
    TooLarge,
    Unavailable,
}

impl ErrorPage {
    pub const ALL: [ErrorPage; 7] = [
        ErrorPage::Expired,
        ErrorPage::Failed,
        ErrorPage::Forbidden,
        ErrorPage::NotFound,
        ErrorPage::BadRequest,
        ErrorPage::TooLarge,
        ErrorPage::Unavailable,
    ];

    pub fn from_fail(kind: FailKind) -> ErrorPage {
        match kind {
            FailKind::Expired => ErrorPage::Expired,
            FailKind::Failed => ErrorPage::Failed,
            FailKind::Forbidden => ErrorPage::Forbidden,
            FailKind::Unavailable => ErrorPage::Unavailable,
        }
    }

    pub fn status(self) -> u16 {
        match self {
            ErrorPage::Expired | ErrorPage::Failed | ErrorPage::BadRequest => 400,
            ErrorPage::Forbidden => 403,
            ErrorPage::NotFound => 404,
            ErrorPage::TooLarge => 413,
            ErrorPage::Unavailable => 503,
        }
    }

    pub fn title_key(self) -> &'static str {
        match self {
            ErrorPage::Expired => "error.expired.title",
            ErrorPage::Failed => "error.failed.title",
            ErrorPage::Forbidden => "error.forbidden.title",
            ErrorPage::NotFound => "error.notfound.title",
            ErrorPage::BadRequest => "error.bad_request.title",
            ErrorPage::TooLarge => "error.too_large.title",
            ErrorPage::Unavailable => "error.unavailable.title",
        }
    }

    pub fn body_key(self) -> &'static str {
        match self {
            ErrorPage::Expired => "error.expired.body",
            ErrorPage::Failed => "error.failed.body",
            ErrorPage::Forbidden => "error.forbidden.body",
            ErrorPage::NotFound => "error.notfound.body",
            ErrorPage::BadRequest => "error.bad_request.body",
            ErrorPage::TooLarge => "error.too_large.body",
            ErrorPage::Unavailable => "error.unavailable.body",
        }
    }
}

/// A provider as the chooser shows it.
pub struct ChoiceView {
    pub id: String,
    pub display_name: String,
    pub available: bool,
}

impl From<&ProviderChoice> for ChoiceView {
    fn from(p: &ProviderChoice) -> Self {
        ChoiceView {
            id: p.id.to_string(),
            display_name: p.display_name.clone(),
            available: p.available,
        }
    }
}

#[derive(Template)]
#[template(path = "chooser.html")]
pub struct Chooser<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub txn: &'a str,
    pub providers: &'a [ChoiceView],
}

/// No field can carry a password value back into the rendered page.
#[derive(Template)]
#[template(path = "password.html")]
pub struct PasswordForm<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub provider_id: &'a str,
    pub provider_name: &'a str,
    pub csrf: &'a str,
    pub challenge: &'a str,
    pub rejected: bool,
}

#[derive(Template)]
#[template(path = "retry.html")]
pub struct Retry<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub state: &'a str,
}

#[derive(Template)]
#[template(path = "retry_exhausted.html")]
pub struct RetryExhausted<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
}

#[derive(Template)]
#[template(path = "continue.html")]
pub struct Continue<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub txn: &'a str,
    pub host: &'a str,
}

#[derive(Template)]
#[template(path = "switch.html")]
pub struct Switch<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub txn: &'a str,
    pub host: &'a str,
    pub current_account: &'a str,
    pub incoming_account: &'a str,
}

#[derive(Template)]
#[template(path = "logout.html")]
pub struct Logout<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    /// The logout ticket and the application it names (`/_hopae/logout`).
    pub txn: Option<&'a str>,
    pub app_name: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "signed_out.html")]
pub struct SignedOut<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    /// "Sign in again to <app>": the validated return target of a logout ticket.
    pub app_name: Option<&'a str>,
    pub sign_in: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "link_notice.html")]
pub struct LinkNotice<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub via_provider: Option<&'a str>,
}

/// `reauth_provider_unavailable`: the provider the session signed in with is
/// disabled or removed; only the sign-out link is offered.
#[derive(Template)]
#[template(path = "reauth_provider_unavailable.html")]
pub struct ReauthProviderUnavailable<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub provider: &'a str,
    pub sign_out: &'a str,
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct Error<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub title_key: &'a str,
    pub body_key: &'a str,
}

/// The portal stylesheet, served at `/assets/portal.css` (the policy allows `style-src 'self'`).
pub const STYLESHEET: &str = include_str!("../../templates/static/portal.css");

/// Render an error page. Falls back to a fixed plain body if rendering fails.
pub fn error_html(page: ErrorPage, t: &Strings, request_id: &str) -> String {
    Error {
        t,
        request_id,
        title_key: page.title_key(),
        body_key: page.body_key(),
    }
    .render()
    .unwrap_or_else(|_| "error".to_string())
}

#[cfg(test)]
mod tests {
    use super::super::i18n::{Lang, strings};
    use super::*;

    #[test]
    fn password_form_posts_bound_challenge_and_escapes_labels_without_prefilling_secret() {
        for lang in [Lang::En, Lang::Ko] {
            let t = strings(lang);
            let page = PasswordForm {
                t,
                request_id: "owned",
                provider_id: "directory",
                provider_name: "<script>owned</script>",
                csrf: "owned-csrf",
                challenge: "owned-challenge",
                rejected: true,
            }
            .render()
            .unwrap();
            assert!(
                page.contains("method=\"post\"")
                    && page.contains("action=\"/login/directory/password\"")
            );
            assert!(page.contains("name=\"csrf\"") && page.contains("name=\"challenge\""));
            assert!(!page.contains("<script>owned</script>"));
            let password = page
                .lines()
                .find(|line| line.contains("id=\"password\"") && line.contains("<input"))
                .unwrap();
            assert!(!password.contains("value="));
            assert!(password.contains("type=\"password\""));
            for key in [
                "password.title",
                "password.provider",
                "password.rejected",
                "password.username",
                "password.password",
                "password.submit",
            ] {
                assert!(t.has(key));
            }
        }
    }
    #[test]
    fn every_error_page_has_text_in_both_languages() {
        for lang in [Lang::En, Lang::Ko] {
            let t = strings(lang);
            for p in ErrorPage::ALL {
                assert!(t.has(p.title_key()), "{lang:?} {}", p.title_key());
                assert!(t.has(p.body_key()), "{lang:?} {}", p.body_key());
                let html = error_html(p, t, "r_test");
                assert!(html.contains("r_test") && html.contains("<h1>"), "{html}");
            }
        }
    }

    #[test]
    fn statuses_follow_the_failure_kind() {
        assert_eq!(ErrorPage::from_fail(FailKind::Expired).status(), 400);
        assert_eq!(ErrorPage::from_fail(FailKind::Failed).status(), 400);
        assert_eq!(ErrorPage::from_fail(FailKind::Forbidden).status(), 403);
        assert_eq!(ErrorPage::from_fail(FailKind::Unavailable).status(), 503);
        assert_eq!(ErrorPage::TooLarge.status(), 413);
        assert_eq!(ErrorPage::NotFound.status(), 404);
    }

    #[test]
    fn stylesheet_has_no_remote_references() {
        assert!(!STYLESHEET.contains("url(") && !STYLESHEET.contains("@import"));
    }
}
