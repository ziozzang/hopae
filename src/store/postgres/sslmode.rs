//! libpq's `sslmode` in a store URL (ADR-0020 decision 6). Hopae always
//! verifies the server's certificate chain against `store.postgres.ca_file`
//! and its host name, which is libpq's `verify-full`; weaker modes are
//! refused by name instead of being silently strengthened or weakened.
//!
//! | `sslmode` | with `ca_file` | without `ca_file` |
//! | --- | --- | --- |
//! | absent | TLS, verify-full | plain, loopback or Unix socket only |
//! | `verify-full` | TLS, verify-full | refused: needs `ca_file` |
//! | `disable` | refused: contradicts `ca_file` | plain, loopback or Unix socket only |
//! | `require`, `verify-ca`, `prefer`, `allow` | refused | refused |
//!
//! The parameter is taken out of the URL before the driver parses it (the
//! driver does not know `verify-*`), in both the URI form
//! (`postgres://…?sslmode=…`) and the key/value form (`… sslmode=…`).

/// What the URL asks for once `sslmode` is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TLS with chain and host-name verification (`ca_file` set).
    VerifyFull,
    /// No TLS: allowed only to loopback or a Unix socket (checked by the caller).
    Plain,
}

/// The URL without `sslmode`, and the transport it selects with `ca`.
pub fn apply(url: &str, ca: bool) -> Result<(String, Transport), String> {
    let (rest, mode) = take(url)?;
    let transport = match (mode.as_deref(), ca) {
        (None, true) | (Some("verify-full"), true) => Transport::VerifyFull,
        (None, false) | (Some("disable"), false) => Transport::Plain,
        (Some("verify-full"), false) => {
            return Err(
                "sslmode=verify-full needs store.postgres.ca_file (the CA that signed the server certificate)".into(),
            );
        }
        (Some("disable"), true) => {
            return Err(
                "sslmode=disable contradicts store.postgres.ca_file: remove one of them".into(),
            );
        }
        (Some(m @ ("require" | "verify-ca" | "prefer" | "allow")), _) => {
            return Err(format!(
                "sslmode={m} is not supported: Hopae verifies the server certificate and its host name; \
                 use sslmode=verify-full with store.postgres.ca_file (or sslmode=disable for loopback or a Unix socket)"
            ));
        }
        (Some(other), _) => {
            return Err(format!(
                "sslmode={} is not a libpq sslmode (expected verify-full or disable)",
                other.chars().take(32).collect::<String>()
            ));
        }
    };
    Ok((rest, transport))
}

/// Remove `sslmode` from either URL form; its value, if present once.
fn take(url: &str) -> Result<(String, Option<String>), String> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let Some((base, query)) = url.split_once('?') else {
            return Ok((url.to_string(), None));
        };
        let mut mode = None;
        let mut kept = Vec::new();
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("sslmode", v)) => {
                    if mode.replace(v.to_ascii_lowercase()).is_some() {
                        return Err("sslmode is given twice".into());
                    }
                }
                _ => kept.push(pair),
            }
        }
        let rest = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
        return Ok((rest, mode));
    }
    // Key/value: `key=value` pairs separated by spaces; values may be
    // single-quoted (with `\'` and `\\` escapes), so scan rather than split.
    let bytes = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let mut mode = None;
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &url[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let vstart = i;
        if i < bytes.len() && bytes[i] == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
        } else {
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        let value = &url[vstart..i];
        if key.is_empty() {
            continue;
        }
        if key == "sslmode" {
            if mode
                .replace(value.trim_matches('\'').to_ascii_lowercase())
                .is_some()
            {
                return Err("sslmode is given twice".into());
            }
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
    }
    Ok((out, mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s600_36_sslmode_verify_full_needs_the_ca_and_is_the_default_with_it() {
        let kv =
            "host=db.example.test user=hopae password='a b\\'c' sslmode=verify-full dbname=hopae";
        let (rest, t) = apply(kv, true).unwrap();
        assert_eq!(t, Transport::VerifyFull);
        assert_eq!(
            rest,
            "host=db.example.test user=hopae password='a b\\'c' dbname=hopae"
        );
        assert!(apply(kv, false).unwrap_err().contains("ca_file"));
        let uri = "postgres://hopae@db.example.test/hopae?sslmode=verify-full&connect_timeout=5";
        let (rest, t) = apply(uri, true).unwrap();
        assert_eq!(
            (rest.as_str(), t),
            (
                "postgres://hopae@db.example.test/hopae?connect_timeout=5",
                Transport::VerifyFull
            )
        );
        assert_eq!(
            apply("host=db user=u", true).unwrap().1,
            Transport::VerifyFull
        );
        assert_eq!(apply("host=db user=u", false).unwrap().1, Transport::Plain);
    }

    #[test]
    fn s600_36_sslmode_weaker_modes_are_refused_by_name_and_disable_is_plain() {
        for m in ["require", "verify-ca", "prefer", "allow"] {
            for ca in [true, false] {
                let e = apply(&format!("host=db sslmode={m}"), ca).unwrap_err();
                assert!(
                    e.contains(&format!("sslmode={m}")) && e.contains("verify-full"),
                    "{e}"
                );
            }
        }
        assert_eq!(
            apply("postgresql://u@127.0.0.1/db?sslmode=disable", false).unwrap(),
            ("postgresql://u@127.0.0.1/db".to_string(), Transport::Plain)
        );
        assert!(
            apply("host=db sslmode=disable", true)
                .unwrap_err()
                .contains("contradicts")
        );
        assert!(
            apply("host=db sslmode=bogus", false)
                .unwrap_err()
                .contains("not a libpq sslmode")
        );
        assert!(
            apply("host=db sslmode=disable sslmode=disable", false)
                .unwrap_err()
                .contains("twice")
        );
    }
}
