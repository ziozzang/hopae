use hopae_grpc::{GATEWAY_PROTO, human_epoch, v1};
use prost::Message;
#[test]
fn additive_fields_and_redaction_are_fixed() {
    let value = v1::HumanFinalRequest {
        binding_contract: 2,
        method: "POST".into(),
        target: "/orders".into(),
        entity_sha256: vec![1; 32],
        entity_length: 4,
        route_id: "orders-route".into(),
        route_revision: 1,
        destination_sha256: vec![2; 32],
        header_policy_revision: 3,
        headers: vec![v1::HumanBoundHeader {
            name: "x-intent".into(),
            present: true,
            value: b"secret-intent".to_vec(),
        }],
    };
    assert_eq!(
        v1::HumanFinalRequest::decode(value.encode_to_vec().as_slice()).unwrap(),
        value
    );
    assert!(!format!("{value:?}").contains("secret-intent"));
    let q = v1::HumanReceiptRequest {
        verification: Some(v1::VerifyRequest {
            request_id: 1,
            headers: vec![v1::Header {
                name: "cookie".into(),
                value: "secret-handle".into(),
            }],
        }),
        service: "orders".into(),
        audience: "api".into(),
        final_request: Some(value),
    };
    assert!(!format!("{q:?}").contains("secret-handle"));
    assert!(GATEWAY_PROTO.contains("uint64 source_revision = 6;"));
    let normalized = GATEWAY_PROTO
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(normalized.contains("service HumanObservedCredentialProjection { rpc Project(ProjectionRequest) returns (ObservedProjectionReply); }"));
    let output = v1::ObservedProjectionReply {
        header_value: b"secret-projected-credential".to_vec(),
        ..Default::default()
    };
    assert!(!format!("{output:?}").contains("secret-projected-credential"));
}
#[test]
fn source_epoch_is_not_a_user_revision_or_credential_generation() {
    let e = human_epoch::encode("owner", 7, 9, "11111111111111111111111111111111").unwrap();
    assert_eq!(e, "hobs1:11111111111111111111111111111111:owner:s:7:a:9");
    assert_eq!(human_epoch::decode(&e).unwrap().source_scope_revision, 7);
    for bad in [
        e.replace(":s:7", ":p:7"),
        e.replace(":s:7", ":s:07"),
        e.replace(":a:9", ":a:0"),
        e.replace("hobs1:", "wobs1:"),
    ] {
        assert!(human_epoch::decode(&bad).is_err());
    }
}
