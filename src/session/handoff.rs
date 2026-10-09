//! Handoff codes (ADR-0004, ADR-0008): minting for a host. Redemption,
//! recovery and the account-switch transaction belong to the verify engine
//! alone (`crate::verify`, integration ruling R-1); the portal only mints.

use std::net::IpAddr;

use url::Url;

use crate::crypto::{Digest, Secret, random_token};
use crate::event::types::{Event, reasons};
use crate::session::service::{CODE_LIFETIME, Service, SessionError, host_of};
use crate::session::transactions::HANDOFF_PARAM;
use crate::session::types::{Aal, SessionId};
use crate::store::StoreError;
use crate::store::types::HandoffCodeRow;

pub struct MintRequest {
    pub session_id: SessionId,
    /// The grant the caller may pass on; the code carries `min(aal_cap, session.aal)`.
    pub aal_cap: Aal,
    /// The clean return target.
    pub target: Url,
    /// The login transaction's `client_ip`, as the application-host verify
    /// recorded it (ADR-0014): never the portal request's address.
    pub client_ip: IpAddr,
    /// Digest of the browser's binding cookie on the application host.
    pub bind_sha256: Digest,
    /// Copied from the minting transaction (never from the client).
    pub recovery_depth: u32,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct MintedHandoff {
    pub code: Secret,
    /// The delivery URL: the host's login entry point carrying the return
    /// target and the reserved parameter ([`landing_location`]).
    pub location: Url,
    pub issued_aal: Aal,
}

/// Characters of a target's path and query that must not stay literal inside
/// the value of the `return` parameter (the target is already percent-encoded
/// ASCII, so only the separators of the carrying query matter).
const RETURN_VALUE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'#')
    .add(b' ');

/// Where a handoff is delivered (ADR-0015): always the application host's
/// login entry point, `https://<host>/_hopae/login?return=<target path and
/// query>&_hopae_handoff=<code>`. Hopae answers that path on every protected
/// host (a whole-host route, or the `site-hopae` route of a path-scoped host),
/// whatever the target's own path is routed to, so the code is always
/// redeemed and never reaches an upstream; redemption plants the handle and
/// redirects to the clean target.
pub fn landing_location(target: &Url, code: &str) -> Url {
    let mut u = target.clone();
    u.set_fragment(None);
    let mut pq = target.path().to_string();
    if let Some(q) = target.query() {
        pq.push('?');
        pq.push_str(q);
    }
    u.set_path("/_hopae/login");
    let enc = percent_encoding::utf8_percent_encode(&pq, RETURN_VALUE);
    u.set_query(Some(&format!("return={enc}&{HANDOFF_PARAM}={code}")));
    u
}

/// Append the reserved parameter to the raw query, leaving every existing
/// parameter byte for byte as it was.
pub fn append_handoff_param(target: &Url, code: &str) -> Url {
    let mut u = target.clone();
    let q = match u.query() {
        Some(q) if !q.is_empty() => format!("{q}&{HANDOFF_PARAM}={code}"),
        _ => format!("{HANDOFF_PARAM}={code}"),
    };
    u.set_query(Some(&q));
    u
}

impl Service {
    /// Mint a handoff code for `req.target`'s host, bound to the application
    /// host's binding cookie digest, the client IP and the session's current
    /// credential generation (ADR-0004/0008). A concurrent revocation or
    /// elevation moves the generation; the mint is retried once against the
    /// new generation and fails if the session is gone.
    pub async fn mint_handoff(&self, req: MintRequest) -> Result<MintedHandoff, SessionError> {
        let host = host_of(&req.target)?;
        // The same predicate the verify engine used to accept the target
        // (ADR-0004), so the portal never mints for a target verify would refuse.
        crate::policy::apps::validate_return_target(
            req.target.as_str(),
            &self.snapshot.load(),
            self.cfg.secure,
        )
        .map_err(SessionError::Refused)?;
        for attempt in 0..2 {
            let session = self
                .sessions
                .session(&req.session_id)
                .await?
                .filter(|s| s.terminated_at.is_none())
                .ok_or(SessionError::Refused(reasons::SESSION_TERMINATED))?;
            let code = random_token(&*self.rng, 32);
            let now = self.clock.now();
            let issued = req.aal_cap.min(session.aal);
            let row = HandoffCodeRow {
                code_sha256: code.digest(),
                session_id: session.session_id.clone(),
                host: host.clone(),
                return_target: req.target.clone(),
                client_ip: req.client_ip,
                bind_sha256: req.bind_sha256,
                issued_aal: issued,
                cred_gen: session.cred_gen,
                recovery_depth: req.recovery_depth,
                created_at: now,
                expires_at: now.add(CODE_LIFETIME),
                consumed_at: None,
                consumed_reason: None,
            };
            match self
                .sessions
                .mint_handoff_code(row, req.events.clone())
                .await
            {
                Ok(()) => {
                    return Ok(MintedHandoff {
                        location: landing_location(&req.target, code.expose()),
                        code,
                        issued_aal: issued,
                    });
                }
                Err(StoreError::Conflict(_)) if attempt == 0 => continue,
                Err(StoreError::Conflict(_)) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Err(SessionError::Refused(reasons::CODE_STALE_GENERATION))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_landing_location_is_the_login_entry_with_the_target_in_return() {
        let t = Url::parse("https://app.example.test:8443/admin/x?q=1&z=%2B2+3").unwrap();
        let l = landing_location(&t, "K");
        assert_eq!(
            l.as_str(),
            "https://app.example.test:8443/_hopae/login?return=/admin/x?q=1%26z=%252B2%2B3&_hopae_handoff=K"
        );
        let (_, back) = l.query_pairs().find(|(k, _)| k == "return").unwrap();
        assert_eq!(back, "/admin/x?q=1&z=%2B2+3");
        let root = landing_location(&Url::parse("https://app.example.test/").unwrap(), "K");
        assert_eq!(
            root.as_str(),
            "https://app.example.test/_hopae/login?return=/&_hopae_handoff=K"
        );
    }

    #[test]
    fn handoff_parameter_is_appended_without_touching_the_rest() {
        let t = Url::parse("https://app.example.test/admin/x?q=1&z=%2B2").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/admin/x?q=1&z=%2B2&_hopae_handoff=K"
        );
        let t = Url::parse("https://app.example.test/admin/x").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/admin/x?_hopae_handoff=K"
        );
        let t = Url::parse("https://app.example.test/?").unwrap();
        assert_eq!(
            append_handoff_param(&t, "K").as_str(),
            "https://app.example.test/?_hopae_handoff=K"
        );
    }
}
