//! Client address and protocol on the portal listener (`trusted_proxies`).
//!
//! Forwarding headers are honored only when the TCP peer is inside a trusted
//! network; otherwise the peer address is the client. Original-URL headers
//! are never consulted: on this listener they are browser input.

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

use crate::gateway::forwarding::{X_FORWARDED_FOR, X_FORWARDED_PROTO};

/// Most forwarded-chain hops (over all header lines) that are believed.
const MAX_HOPS: usize = 64;

/// The client as the portal sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    pub ip: IpAddr,
    pub https: bool,
}

/// Resolve the client from the TCP peer and, for a trusted peer, the
/// forwarding headers: the right-most address in the chain that is not itself
/// trusted (the left-most when every hop is trusted).
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> Client {
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return Client {
            ip: peer,
            https: false,
        };
    }
    let mut chain: Vec<IpAddr> = Vec::new();
    let mut hops = 0usize;
    for v in headers.get_all(&X_FORWARDED_FOR) {
        let Ok(text) = v.to_str() else { continue };
        for part in text.split(',') {
            // More hops than any real proxy chain: the header is not
            // believed. Never cut the chain short, which would drop the
            // right-hand (authoritative) entries and keep an attacker's prefix.
            hops += 1;
            if hops > MAX_HOPS {
                return Client {
                    ip: peer,
                    https: false,
                };
            }
            match part.trim().parse::<IpAddr>() {
                Ok(ip) => chain.push(ip),
                // An unparseable hop breaks the chain: nothing to its left can be believed.
                Err(_) => chain.clear(),
            }
        }
    }
    let ip = chain
        .iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or_else(|| chain.first())
        .copied()
        .unwrap_or(peer);
    let https = headers
        .get(&X_FORWARDED_PROTO)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));
    Client { ip, https }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn nets() -> Vec<IpNet> {
        vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.1.0.0/16".parse().unwrap(),
        ]
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn xff() -> &'static str {
        X_FORWARDED_FOR.as_str()
    }

    fn xfp() -> &'static str {
        X_FORWARDED_PROTO.as_str()
    }

    #[test]
    fn untrusted_peer_ignores_forwarding_headers() {
        let h = headers(&[(xff(), "203.0.113.9"), (xfp(), "https")]);
        let c = resolve("10.0.0.5".parse().unwrap(), &h, &nets());
        assert_eq!(c.ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert!(!c.https);
    }

    #[test]
    fn trusted_peer_uses_the_forwarded_client() {
        let h = headers(&[(xff(), "203.0.113.9"), (xfp(), "https")]);
        let c = resolve("127.0.0.1".parse().unwrap(), &h, &nets());
        assert_eq!(c.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert!(c.https);
    }

    #[test]
    fn spoofed_left_entries_are_skipped_from_the_right() {
        // client-supplied "1.2.3.4" then the real client then a trusted hop.
        let h = headers(&[(xff(), "1.2.3.4, 203.0.113.9, 10.1.2.3")]);
        let c = resolve("127.0.0.1".parse().unwrap(), &h, &nets());
        assert_eq!(c.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        // Several header lines are one chain.
        let h2 = headers(&[(xff(), "1.2.3.4"), (xff(), "203.0.113.9")]);
        let c2 = resolve("127.0.0.1".parse().unwrap(), &h2, &nets());
        assert_eq!(c2.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn garbage_or_missing_headers_fall_back_to_the_peer() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(resolve(peer, &HeaderMap::new(), &nets()).ip, peer);
        let h = headers(&[(xff(), "not-an-ip"), (xfp(), "gopher")]);
        let c = resolve(peer, &h, &nets());
        assert_eq!(c.ip, peer);
        assert!(!c.https);
    }

    #[test]
    fn all_hops_trusted_takes_the_leftmost() {
        let h = headers(&[(xff(), "10.1.0.7, 10.1.0.8")]);
        let c = resolve("127.0.0.1".parse().unwrap(), &h, &nets());
        assert_eq!(c.ip, "10.1.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv6_chain() {
        let h = headers(&[(xff(), "2001:db8::1")]);
        let c = resolve("127.0.0.1".parse().unwrap(), &h, &nets());
        assert_eq!(c.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn the_hop_bound_rejects_overflow_instead_of_truncating_the_right() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let hops = |n: usize, last: &str| {
            let mut v = vec!["198.51.100.7".to_string(); n - 1];
            v.push(last.to_string());
            v.join(", ")
        };
        // 64 hops: honored, the right-most untrusted one wins.
        let h = headers(&[(xff(), &hops(64, "203.0.113.9"))]);
        assert_eq!(
            resolve(peer, &h, &nets()).ip,
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // 65 hops (an attacker prefix of 64 copies and the real client last):
        // the header is not believed at all; the peer is the client. The
        // client-controlled prefix never becomes the client address.
        let h = headers(&[(xff(), &hops(65, "203.0.113.9"))]);
        let c = resolve(peer, &h, &nets());
        assert_eq!(c.ip, peer);
        assert!(!c.https);
        // The bound counts hops over every header line.
        let h = headers(&[
            (xff(), &hops(40, "198.51.100.7")),
            (xff(), &hops(25, "203.0.113.9")),
        ]);
        assert_eq!(resolve(peer, &h, &nets()).ip, peer);
        let h = headers(&[
            (xff(), &hops(40, "198.51.100.7")),
            (xff(), &hops(24, "203.0.113.9")),
        ]);
        assert_eq!(
            resolve(peer, &h, &nets()).ip,
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }
}
