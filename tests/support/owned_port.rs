//! Pure test-fixture readiness parsing, never authentication evidence.
/// An empty/partial file must never become an origin's implicit HTTPS port443.
pub(crate) fn parse(value: &str) -> Result<u16, &'static str> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("owned readiness requires canonical nonzero u16 port");
    }
    let port: u16 = value.parse().map_err(|_| "owned readiness port overflow")?;
    if port == 0 || port.to_string() != value {
        return Err("owned readiness requires canonical nonzero u16 port");
    }
    Ok(port)
}
#[cfg(test)]
mod tests {
    #[test]
    fn empty_readiness_would_select_https_default_without_the_fixture_guard() {
        let empty_ready = "";
        let endpoint = url::Url::parse(&format!("https://127.0.0.1:{empty_ready}")).unwrap();
        assert_eq!(endpoint.port_or_known_default(), Some(443));
        assert!(super::parse(empty_ready).is_err());
    }
    #[test]
    fn rejects_empty_default_port_fallback_and_noncanonical_ports() {
        for value in [
            "",
            "0",
            "00",
            "01",
            "00080",
            "+443",
            "-1",
            "65536",
            "999999",
            "443\n",
            " 443",
            "443 ",
            "４４３",
            "443.0",
            "443/path",
        ] {
            assert!(
                super::parse(value).is_err(),
                "invalid readiness was accepted"
            );
        }
        for (value, expected) in [("1", 1), ("443", 443), ("65535", 65535)] {
            assert_eq!(super::parse(value), Ok(expected));
        }
    }
}
