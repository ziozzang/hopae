//! Provider-independent versioned gateway gRPC contract.
pub mod v1 {
    tonic::include_proto!("hangang.hopae.v1");
}

pub mod request_binding;
pub mod request_binding_v2;

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

pub mod human_epoch;
pub mod service_epoch;
pub mod workload_epoch;

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

// The observed endpoint carries the same sensitive credential bytes.
impl std::fmt::Debug for v1::ObservedProjectionReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedProjectionReply")
            .field("request_id", &self.request_id)
            .field("header_value", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod projection_privacy_tests {
    #[test]
    fn observed_projection_debug_redacts_credential_bytes() {
        let reply = super::v1::ObservedProjectionReply {
            request_id: 1,
            header_value: b"observed-private-projection-value".to_vec(),
            ..Default::default()
        };
        let debug = format!("{reply:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("observed-private-projection-value"));
        assert!(!debug.contains("111, 98, 115"));
    }
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

/// Native client endpoint input: fixed PEM or a reloadable rustls configuration.
#[cfg(feature = "native-client")]
pub mod client_endpoint;

#[cfg(feature = "native-client")]
pub mod observed_client;

// Workload wire requests can contain a raw projected Kubernetes token. New
// debug implementations never recurse into verification headers or proof bytes.
impl std::fmt::Debug for v1::WorkloadReceiptRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadReceiptRequest")
            .field("verification", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for v1::WorkloadReceiptReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadReceiptReply")
            .field("request_id", &self.request_id)
            .field("receipt", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for v1::WorkloadReceiptObservationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadReceiptObservationRequest")
            .field("request_id", &self.request_id)
            .field("receipt", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Workload-only opaque observed authentication; never a permission grant.
#[cfg(feature = "native-client")]
pub mod workload_observed_client;

// Human descriptors and proof bytes must not appear in default debug logs.
macro_rules! redacted_human_debug {
    ($($ty:ty),+ $(,)?) => {$ (
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Human wire metadata { [REDACTED] }")
            }
        }
    )+};
}
redacted_human_debug!(
    v1::HumanBoundHeader,
    v1::HumanFinalRequest,
    v1::HumanReceiptRequest,
    v1::HumanReceiptReply,
    v1::HumanReceiptObservedReply,
    v1::HumanReceiptObservationRequest
);

#[cfg(feature = "native-client")]
pub mod human_observed_client;

pub mod human_scope;
