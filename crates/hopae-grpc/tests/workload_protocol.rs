//! Additive wire availability, old wire compatibility, and token redaction.
use hopae_grpc::v1;
use prost::Message;
#[test]
fn dedicated_services_and_existing_methods_compile() {
    // Generated clients/servers are available, but declarations do not register
    // a production handler. Old Service API names stay compile-compatible.
    fn new_api<T: v1::workload_authentication_receipts_server::WorkloadAuthenticationReceipts>() {}
    fn output_api<
        T: v1::workload_observed_credential_projection_server::WorkloadObservedCredentialProjection,
    >() {
    }
    let _ = new_api::<NeverRegistered>;
    let _ = output_api::<NeverRegistered>;
    let _ = v1::authentication_receipts_client::AuthenticationReceiptsClient::<
        tonic::transport::Channel,
    >::new;
    let _ = v1::observed_credential_projection_client::ObservedCredentialProjectionClient::<
        tonic::transport::Channel,
    >::new;
    let _ = v1::workload_authentication_receipts_client::WorkloadAuthenticationReceiptsClient::<
        tonic::transport::Channel,
    >::new;
    let _ = v1::workload_observed_credential_projection_client::WorkloadObservedCredentialProjectionClient::<tonic::transport::Channel>::new;
}
struct NeverRegistered;
#[tonic::async_trait]
impl v1::workload_authentication_receipts_server::WorkloadAuthenticationReceipts
    for NeverRegistered
{
    async fn issue_observed(
        &self,
        _: tonic::Request<v1::WorkloadReceiptRequest>,
    ) -> Result<tonic::Response<v1::WorkloadReceiptObservedReply>, tonic::Status> {
        Err(tonic::Status::unimplemented("protocol only"))
    }
    async fn observe_time(
        &self,
        _: tonic::Request<v1::WorkloadReceiptObservationRequest>,
    ) -> Result<tonic::Response<v1::WorkloadReceiptTimeReply>, tonic::Status> {
        Err(tonic::Status::unimplemented("protocol only"))
    }
}
#[tonic::async_trait]
impl v1::workload_observed_credential_projection_server::WorkloadObservedCredentialProjection
    for NeverRegistered
{
    async fn project(
        &self,
        _: tonic::Request<v1::ProjectionRequest>,
    ) -> Result<tonic::Response<v1::ObservedProjectionReply>, tonic::Status> {
        Err(tonic::Status::unimplemented("protocol only"))
    }
}
#[test]
fn workload_fields_have_fixed_tags_and_service_wire_is_unchanged() {
    let service = v1::ServiceReceiptTimeReply {
        request_id: 1,
        owner_now_ms: 2,
        remaining_ms: 3,
        receipt_sha256: vec![4],
        clock_domain: "n".into(),
        profile_revision: 6,
        application_generation: 7,
        key_registry_revision: 8,
        cache_ttl_ms: 0,
    };
    let expected = vec![
        8, 1, 16, 2, 24, 3, 34, 1, 4, 42, 1, b'n', 48, 6, 56, 7, 64, 8,
    ];
    assert_eq!(service.encode_to_vec(), expected);
    let workload = v1::WorkloadReceiptTimeReply {
        request_id: 1,
        owner_now_ms: 2,
        remaining_ms: 3,
        receipt_sha256: vec![4],
        clock_domain: "n".into(),
        profile_revision: 6,
        application_generation: 7,
        key_registry_revision: 8,
        cache_ttl_ms: 0,
    };
    assert_eq!(workload.encode_to_vec(), expected);
    // Equal wire shapes are deliberately NOT evidence of equal endpoint trust.
    let request = v1::WorkloadReceiptRequest {
        verification: None,
        service: "s".into(),
        audience: "a".into(),
        request_sha256: vec![4],
    };
    assert_eq!(
        request.encode_to_vec(),
        vec![18, 1, b's', 26, 1, b'a', 34, 1, 4]
    );
    let query = v1::ProjectionRequest {
        request_id: 1,
        permission_contract: 3,
        permission_query: vec![4],
    };
    assert_eq!(query.encode_to_vec(), vec![8, 1, 16, 3, 26, 1, 4]);
}
#[test]
fn new_request_and_nested_proof_debug_never_expose_token_or_receipt_bytes() {
    let secret = b"synthetic-workload-private-token".to_vec();
    let request = v1::WorkloadReceiptRequest {
        verification: Some(v1::VerifyRequest {
            request_id: 1,
            headers: vec![v1::Header {
                name: "authorization".into(),
                value: secret.clone(),
            }],
        }),
        ..Default::default()
    };
    let reply = v1::WorkloadReceiptObservedReply {
        receipt: Some(v1::WorkloadReceiptReply {
            request_id: 1,
            receipt: secret.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let observe = v1::WorkloadReceiptObservationRequest {
        receipt: secret,
        ..Default::default()
    };
    for debug in [
        format!("{request:?}"),
        format!("{reply:?}"),
        format!("{observe:?}"),
    ] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("synthetic-workload-private-token"));
        assert!(!debug.contains("115, 121, 110"));
        assert!(!debug.contains("authorization"));
    }
}
