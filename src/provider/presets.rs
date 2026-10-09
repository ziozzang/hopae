//! Built-in provider presets (ADR-0010): defaults the operator can override
//! in the provider's `config`. Kakao and Naver arrive in M3; the table keeps
//! the shape they need.

/// Defaults for one well-known provider.
#[derive(Debug, PartialEq, Eq)]
pub struct Preset {
    pub name: &'static str,
    pub issuer: &'static str,
    pub scope: &'static str,
    /// Call the user-info endpoint after the ID token is validated. Google's
    /// ID token already carries every claim Hopae uses, so the extra round
    /// trip (and failure point) is off.
    pub userinfo: bool,
    /// Hosts, besides the issuer's own, that the provider's discovery document
    /// legitimately points to (token, keys, user info). Anything else it
    /// names is refused (G7-IDP-03).
    pub endpoint_hosts: &'static [&'static str],
}

pub const GOOGLE: Preset = Preset {
    name: "google",
    issuer: "https://accounts.google.com",
    scope: "openid email profile",
    userinfo: false,
    endpoint_hosts: &[
        "accounts.google.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "openidconnect.googleapis.com",
    ],
};

// M3: KAKAO (issuer https://kauth.kakao.com, user-info mapping, secret required)
// and NAVER (kind oauth2) are added here.
const ALL: [&Preset; 1] = [&GOOGLE];

/// The preset of this name, if any.
pub fn by_name(name: &str) -> Option<&'static Preset> {
    ALL.into_iter().find(|p| p.name == name)
}

/// The preset whose issuer is exactly `issuer`.
pub fn by_issuer(issuer: &str) -> Option<&'static Preset> {
    ALL.into_iter().find(|p| p.issuer == issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup() {
        assert_eq!(by_name("google"), Some(&GOOGLE));
        assert_eq!(by_issuer("https://accounts.google.com"), Some(&GOOGLE));
        assert_eq!(by_issuer("https://accounts.google.com/"), None);
        assert_eq!(by_name("kakao"), None);
    }
}
