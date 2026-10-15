//! Provider-independent versioned gateway gRPC contract.
pub mod v1 {
    tonic::include_proto!("hangang.hopae.v1");
}

pub mod request_binding;

pub mod receipt;
pub mod receipt_time;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    Human,
    Service,
    Workload,
    Network,
}

pub mod receipt_binding;

pub mod receipt_keys;

pub mod service_epoch;

/// Canonical schema for build-time consumers sharing the generated v1 types.
pub const GATEWAY_PROTO: &str = include_str!("../proto/gateway.proto");

// Credential bodies must never enter default protobuf debug logging.
impl std::fmt::Debug for v1::ProjectionReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionReply")
            .field("request_id", &self.request_id)
            .field("header_value", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod projection_privacy_tests {
    #[test]
    fn default_projection_debug_redacts_credential_bytes() {
        let reply = super::v1::ProjectionReply {
            request_id: 1,
            header_value: b"owned-private-projection-value".to_vec(),
            ..Default::default()
        };
        let debug = format!("{reply:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("owned-private-projection-value"));
        assert!(!debug.contains("111, 119, 110"));
    }
}
