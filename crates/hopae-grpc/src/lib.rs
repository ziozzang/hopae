//! Provider-independent versioned gateway gRPC contract.
pub mod v1 {
    tonic::include_proto!("hangang.hopae.v1");
}

pub mod request_binding;

pub mod receipt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    Human,
    Service,
    Workload,
    Network,
}

pub mod receipt_binding;

pub mod receipt_keys;
