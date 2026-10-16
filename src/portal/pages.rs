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
    /// Passwordless sign-in: (ceremony bearer, options JSON) (ADR-0017 decision 16).
    pub passkey: Option<(&'a str, &'a str)>,
    pub passkey_csrf: &'a str,
    pub passkey_error: Option<&'static str>,
    pub integrity: &'a str,
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
    fn security_pages_render_in_both_languages_and_escape_user_text() {
        use super::super::settings::{PasskeyView, SecurityView};
        let view = SecurityView {
            passkeys: vec![PasskeyView {
                id: "AAAA".into(),
                label: "<b>mine</b>".into(),
                synced: true,
                high_assurance: false,
                created_at: crate::crypto::Timestamp::from_secs(0),
                last_used_at: None,
            }],
            recovery_required: true,
            can_verify: true,
            ..SecurityView::default()
        };
        for lang in [Lang::En, Lang::Ko] {
            let t = strings(lang);
            let overview = SecurityPage {
                t,
                request_id: "r_1",
                notice: Some("notice.added"),
                error: None,
                view: &view,
                passkey_count: "1".into(),
                recovery_count: "0".into(),
                has_factor: true,
            }
            .render()
            .unwrap();
            assert!(overview.contains("role=\"alert\"") && !overview.contains("<script"));
            let list = PasskeysPage {
                t,
                request_id: "r_1",
                notice: None,
                error: Some("passkeys.last_factor"),
                passkeys: vec![PasskeyRow {
                    id: "AAAA".into(),
                    label: "<b>mine</b>".into(),
                    kind: "passkeys.synced",
                    created: "2026-10-16 09:00 UTC".into(),
                    last_used: None,
                }],
                csrf_rename: "c1",
                csrf_remove: "c2",
                only_factor: true,
                high_assurance: false,
            }
            .render()
            .unwrap();
            assert!(!list.contains("<b>mine</b>") && list.contains("&#60;b&#62;mine"));
            assert!(
                !list.contains("action=\"/security/passkeys/remove\""),
                "the only factor has no remove form"
            );
            let new = PasskeyNewPage {
                t,
                request_id: "r_1",
                notice: None,
                error: None,
                csrf: "c",
                ceremony: "x",
                options: "{\"publicKey\":{\"x\":\"</script><script>\"}}",
                high_assurance: false,
                integrity: script_integrity(),
            }
            .render()
            .unwrap();
            assert!(new.contains("<script src=\"/assets/webauthn.js\" integrity=\"sha384-"));
            assert_eq!(new.matches("<script").count(), 1, "only the static script");
            assert!(new.contains("<noscript>") && new.contains("data-msg-cancelled"));
            for html in [&overview, &list, &new] {
                let html = html.replace("/assets/webauthn.js", "");
                for prefix in [
                    "security.",
                    "passkeys.",
                    "passkey_new.",
                    "webauthn.",
                    "notice.",
                    "refusal.",
                ] {
                    let leaked = html.match_indices(prefix).any(|(i, _)| {
                        html[i + prefix.len()..].starts_with(|c: char| c.is_ascii_lowercase())
                    });
                    assert!(!leaked, "{lang:?}: untranslated {prefix} key in {html}");
                }
            }
        }
    }

    #[test]
    fn stylesheet_has_no_remote_references() {
        assert!(!STYLESHEET.contains("url(") && !STYLESHEET.contains("@import"));
    }
}

#[derive(Template)]
#[template(path = "totp.html")]
pub struct TotpPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub enrollment: &'a str,
    pub manual_key: &'a str,
    pub complete: bool,
}

#[derive(Template)]
#[template(path = "stepup.html")]
pub struct StepUpPage<'a> {
    pub enrollment_required: bool,
    /// Passkeys are configured: the setup link goes to the security overview.
    pub setup_any: bool,
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub transaction: &'a str,
    pub csrf: &'a str,
}

pub struct ExternalChoice {
    pub label: String,
    pub location: String,
}
#[derive(Template)]
#[template(path = "stepup_choices.html")]
pub struct StepUpChoicesPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub transaction: &'a str,
    pub totp: bool,
    pub choices: &'a [ExternalChoice],
}
#[derive(Template)]
#[template(path = "stepup_external.html")]
pub struct ExternalStepUpPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub transaction: &'a str,
    pub factor: &'a str,
    pub csrf: &'a str,
}

// ---- Security settings and passkeys (ADR-0017) ---------------------------

/// The only portal script (ADR-0017 decision 3).
pub const CEREMONY_SCRIPT: &str = include_str!("../../templates/static/webauthn.js");

/// `sha384-…` Subresource Integrity value of [`CEREMONY_SCRIPT`].
pub fn script_integrity() -> &'static str {
    static SRI: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SRI.get_or_init(|| {
        use base64::Engine as _;
        use sha2::Digest as _;
        let digest = sha2::Sha384::digest(CEREMONY_SCRIPT.as_bytes());
        format!(
            "sha384-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    })
}

#[derive(Template)]
#[template(path = "security_signin.html")]
pub struct SecuritySignInPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub title_key: &'a str,
    pub body_key: &'a str,
    pub alert: bool,
}

#[derive(Template)]
#[template(path = "security.html")]
pub struct SecurityPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub view: &'a super::settings::SecurityView,
    pub passkey_count: String,
    pub recovery_count: String,
    pub has_factor: bool,
}

/// One row of the passkey list.
pub struct PasskeyRow {
    pub id: String,
    pub label: String,
    /// i18n key of the kind badge.
    pub kind: &'static str,
    pub created: String,
    pub last_used: Option<String>,
}

#[derive(Template)]
#[template(path = "passkeys.html")]
pub struct PasskeysPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub passkeys: Vec<PasskeyRow>,
    pub csrf_rename: &'a str,
    pub csrf_remove: &'a str,
    pub only_factor: bool,
    pub high_assurance: bool,
}

#[derive(Template)]
#[template(path = "passkey_remove.html")]
pub struct PasskeyRemovePage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub csrf: &'a str,
    pub id: &'a str,
    pub label: &'a str,
}

#[derive(Template)]
#[template(path = "passkey_new.html")]
pub struct PasskeyNewPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub csrf: &'a str,
    pub ceremony: &'a str,
    pub options: &'a str,
    pub high_assurance: bool,
    pub integrity: &'a str,
}

#[derive(Template)]
#[template(path = "security_verify.html")]
pub struct VerifyPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub csrf: &'a str,
    pub next: &'a str,
    /// (ceremony bearer, options JSON)
    pub passkey: Option<(String, String)>,
    pub totp: bool,
    pub recovery: bool,
    pub integrity: &'a str,
}

#[derive(Template)]
#[template(path = "recovery_codes.html")]
pub struct RecoveryPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub csrf: &'a str,
    /// Shown once, right after generation.
    pub codes: Vec<String>,
    pub first: bool,
    pub generated: bool,
    pub unused: String,
    pub has_factor: bool,
}

#[derive(Template)]
#[template(path = "stepup_passkey.html")]
pub struct StepUpPasskeyPage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
    pub notice: Option<&'static str>,
    pub error: Option<&'static str>,
    pub csrf: &'a str,
    pub transaction: &'a str,
    pub ceremony: &'a str,
    pub options: &'a str,
    pub totp: bool,
    pub choices: &'a [ExternalChoice],
    pub integrity: &'a str,
    /// The page needs a high-assurance security key (an AAL 3 rule,
    /// ADR-0018): only such keys are offered and no other method is listed.
    pub high_assurance: bool,
}

/// An AAL 3 step-up for a user without a qualifying security key.
#[derive(Template)]
#[template(path = "stepup_high_assurance.html")]
pub struct StepUpHighAssurancePage<'a> {
    pub t: &'a Strings,
    pub request_id: &'a str,
}
