//! `hopae --check`: validate, then print what the operator must register
//! elsewhere (scenario 013-1). Secrets are referenced by variable *name*;
//! no value ever reaches the output.

use std::fmt::Write as _;
use std::time::Duration;

use crate::config::Config;
use crate::policy::types::{BindingPolicy, IpBinding, OnMismatch, UaBinding};

#[path = "../gateway/preflight.rs"]
mod gateway_facts;

/// The overlap between two caller keys that is worth a warning.
pub const KEY_OVERLAP_WARN: Duration = Duration::from_secs(7 * 24 * 3600);

/// `YYYY-MM-DD` for a unix time (UTC), without a date library.
pub fn iso_date(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a unix time (UTC).
pub fn iso_datetime(unix_secs: i64) -> String {
    let rem = unix_secs.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        iso_date(unix_secs),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn dur(d: Duration) -> String {
    let s = d.as_secs();
    if s > 0 && s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s > 0 && s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s > 0 && s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

fn binding(b: &BindingPolicy) -> String {
    let ip = match b.ip {
        IpBinding::Strict => "strict".to_string(),
        IpBinding::Prefix { v4, v6 } => format!("prefix(/{v4},/{v6})"),
        IpBinding::Off => "off".to_string(),
    };
    let ua = match b.ua {
        UaBinding::Strict => "strict",
        UaBinding::Off => "off",
    };
    let on = match b.on_mismatch {
        OnMismatch::TerminateSession => "terminate_session",
        OnMismatch::DropHandle => "drop_handle",
    };
    format!("ip={ip} ua={ua} on_mismatch={on}")
}

/// Everything a clean `--check` prints on stdout, ending with `config ok`.
pub fn report(cfg: &Config) -> String {
    report_with(cfg, &[])
}

/// `report` with the stored provider rows applied: a stored `reauth` setting
/// (an api-managed row) overrides the file's default capability, as it does
/// at start.
pub fn report_with(cfg: &Config, stored: &[crate::store::types::ProviderRow]) -> String {
    let mut snap = cfg.snapshot(0);
    crate::provider::apply_stored_reauth(&mut snap, stored);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "hopae {}: configuration check",
        env!("CARGO_PKG_VERSION")
    );

    let _ = writeln!(out, "listeners:");
    let _ = writeln!(
        out,
        "  portal   {}  (public url {})",
        cfg.portal_addr(),
        cfg.portal.public_url.trim_end_matches('/')
    );
    let _ = writeln!(out, "  gateway  {}", cfg.gateway_addr());
    if let (Some(addr), Some(url)) = (cfg.admin_addr(), cfg.admin.public_url.as_deref()) {
        let _ = writeln!(
            out,
            "  admin    {addr}  (public url {})",
            url.trim_end_matches('/')
        );
    }
    let _ = writeln!(out, "store: sqlite {}", cfg.store_path().display());

    let _ = writeln!(out, "applications:");
    let mut origins: Vec<String> = Vec::new();
    let scheme = if cfg.cookie.secure { "https" } else { "http" };
    let default_port = if cfg.cookie.secure { 443 } else { 80 };
    for a in &snap.apps {
        let hosts: Vec<&str> = a.hosts.iter().map(|h| h.as_str()).collect();
        let ports: Vec<String> = a.ports.iter().map(u16::to_string).collect();
        let implicit = if cfg.admin_enabled() && a.app_id.as_str() == "admin" {
            ", implicit"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "  {} ({}{implicit}): hosts {}; ports {}; {}; session idle {} absolute {}; on_authz_change {:?}; verify_cache_seconds {}; logout_confirm {}{}{}",
            a.app_id,
            if a.enabled { "enabled" } else { "disabled" },
            hosts.join(", "),
            ports.join(", "),
            binding(&a.binding),
            dur(a.session.idle),
            dur(a.session.absolute),
            a.on_authz_change,
            a.verify_cache_seconds,
            a.logout_confirm,
            a.max_auth_age
                .map(|n| format!("; max_auth_age {}", dur(n)))
                .unwrap_or_default(),
            if a.step_up.is_empty() {
                String::new()
            } else {
                format!(
                    "; step_up rules {} (parsed, enforced from M5, force no-store)",
                    a.step_up.len()
                )
            },
        );
        if a.enabled {
            for h in &a.hosts {
                for p in &a.ports {
                    origins.push(if *p == default_port {
                        format!("{scheme}://{h}")
                    } else {
                        format!("{scheme}://{h}:{p}")
                    });
                }
            }
        }
    }
    let d = &snap.default_app;
    let _ = writeln!(
        out,
        "  default (policy defaults only): {}; session idle {} absolute {}; verify_cache_seconds {}",
        binding(&d.binding),
        dur(d.session.idle),
        dur(d.session.absolute),
        d.verify_cache_seconds
    );

    let _ = writeln!(
        out,
        "return origins (each is a credential destination you vouch for):"
    );
    if origins.is_empty() {
        let _ = writeln!(out, "  (none: no enabled application)");
    }
    for o in &origins {
        let _ = writeln!(out, "  {o}");
    }

    let _ = writeln!(out, "providers:");
    if snap.providers.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    let base = cfg.portal.public_url.trim_end_matches('/');
    for p in &snap.providers {
        let _ = writeln!(
            out,
            "  {}: {}; redirect_uri {base}/callback/{}; managed_by=file; {}; secret from {}",
            p.provider_id,
            p.kind.as_str(),
            p.provider_id,
            if p.enabled { "enabled" } else { "disabled" },
            p.client_secret_env.as_deref().unwrap_or("(none)"),
        );
    }

    let _ = writeln!(
        out,
        "identity headers (relayed upstream, set by Hopae only): {}",
        gateway_facts::IDENTITY_HEADERS.join(", ")
    );
    let _ = writeln!(out, "verify budget: {} ms", cfg.gateway.verify_budget_ms);
    let staleness = snap
        .apps
        .iter()
        .map(|a| a.verify_cache_seconds)
        .chain(std::iter::once(snap.default_app.verify_cache_seconds))
        .max()
        .unwrap_or(0);
    let _ = writeln!(out, "verify cache staleness bound: {staleness} s");

    let _ = writeln!(
        out,
        "caller key: Hopae reads {}; give the gateway the same value (as {} in its environment)",
        cfg.gateway
            .caller_key_env
            .as_deref()
            .unwrap_or("(none: development mode)"),
        gateway_facts::GATEWAY_KEY_ENV
    );
    if let Some(next) = &cfg.gateway.caller_key_next_env {
        let _ = writeln!(
            out,
            "next caller key (rotation overlap): Hopae also accepts {next}"
        );
    }
    let verify_url = format!(
        "http://{}{}",
        cfg.gateway_addr(),
        crate::gateway::hangang::VERIFY_PATH
    );
    let timeout = (cfg.gateway.verify_budget_ms + 100).min(5000);
    let _ = writeln!(
        out,
        "gateway route auth fragment (register it on every protected route; the key is the variable name, never a value):"
    );
    let names = cfg.cookie_names();
    let mut fragment = gateway_facts::route_auth_fragment(&verify_url, timeout);
    if let Some(native) = &cfg.listen.native_gateway {
        fragment["native"] = serde_json::json!({"address":native,"pool_size":32});
    }
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(&fragment).unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "gateway route field strip_request_cookies (HC-12: set it on every route that reaches an application upstream, public routes of a path-scoped host included; the gateway removes these cookies from the request it forwards):"
    );
    let strip = gateway_facts::route_strip_fragment(&[&names.handle, &names.bind]);
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(&strip).unwrap_or_default()
    );
    if let (Some(host), Some(limits)) = (cfg.admin_host(), cfg.admin_limits()) {
        let admin_addr = cfg.admin_addr().map(|a| a.to_string()).unwrap_or_default();
        let _ = writeln!(
            out,
            "gateway route for the console host (id hopae-admin; no strip_request_cookies: the console reads its own handle cookie; the gateway must reach the admin listener {admin_addr}):"
        );
        let route = gateway_facts::route_console_fragment(
            host.0.as_str(),
            &format!("http://{admin_addr}"),
            &verify_url,
            timeout,
        );
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&route).unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "admin.untrusted_peers {}",
            match limits.untrusted_peers {
                crate::config::UntrustedPeers::Refuse => "refuse",
                crate::config::UntrustedPeers::AsClient => "as_client",
            }
        );
        for p in snap.providers.iter().filter(|p| p.enabled) {
            let _ = writeln!(
                out,
                "  {}: reauth {}",
                p.provider_id,
                match p.reauth {
                    crate::provider::types::ReauthCapability::MaxAge =>
                        "max_age: console freshness is a provider-verified challenge",
                    crate::provider::types::ReauthCapability::Unsupported =>
                        "unsupported: console freshness is Hopae login age; enforce a second factor at the provider for administrators",
                }
            );
        }
    }
    let _ = writeln!(out, "config ok");
    out
}

/// Non-fatal findings, in the order `--check` prints them. `next_since` is the
/// unix time the `caller_key_next_env` overlap began, when known.
pub fn warnings(
    cfg: &Config,
    lookup: impl Fn(&str) -> Option<String>,
    next_since: Option<i64>,
    now_secs: i64,
) -> Vec<String> {
    let mut w = cfg.warnings();
    w.extend(crate::config::env_warnings(cfg, lookup));
    if cfg.gateway.caller_key_next_env.is_some()
        && let Some(since) = next_since
        && now_secs - since > KEY_OVERLAP_WARN.as_secs() as i64
    {
        w.push(format!(
            "caller_key_next_env configured since {}: finish the rotation or remove it",
            iso_date(since)
        ));
    }
    w
}

/// A warning line as printed: `WARNING:` lines are already loud, the rest get `warning: `.
pub fn render_warning(w: &str) -> String {
    if w.starts_with("WARNING") {
        w.to_string()
    } else {
        format!("warning: {w}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_date_is_correct() {
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(1_800_000_000), "2027-01-15");
        assert_eq!(iso_date(951_782_400), "2000-02-29");
        assert_eq!(iso_date(-86_400), "1969-12-31");
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(dur(Duration::from_secs(43_200)), "12h");
        assert_eq!(dur(Duration::from_secs(7 * 86_400)), "7d");
        assert_eq!(dur(Duration::from_secs(90)), "90s");
    }
}
