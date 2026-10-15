//! Real native Source/SDK/Pum/paired-ledger qualification. Network and route
//! owners below are fixed authenticated fixtures, not the actual Sum/Root chain.
use super::native_rpc_tests::{CALLER, headers, native, scope, services, tls};
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hopae_grpc::{human_observed_client as sdk, receipt_time::ClockRates, v1};
use sha2::{Digest as _, Sha256};
use std::sync::atomic::AtomicBool;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig},
};
const ORIGIN: &str = "owned-paired-projection-secret";
struct NeverPolled(Arc<std::sync::atomic::AtomicUsize>);
impl http_body::Body for NeverPolled {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.0.fetch_add(1, Ordering::AcqRel);
        panic!("unauthenticated contract4 protobuf body polled");
    }
}
async fn contract4_predecode(services: &crate::app::Services) {
    use tower::ServiceExt;
    for credentials in [
        vec![],
        vec!["Bearer incorrect"],
        vec!["Bearer incorrect", "Bearer incorrect"],
        vec![
            "Bearer native-human-rpc-owned-caller-thirty-two-bytes",
            "Bearer incorrect",
        ],
    ] {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/hangang.hopae.v1.HumanObservedCredentialProjection/Project")
            .header("content-type", "application/grpc")
            .body(axum::body::Body::new(NeverPolled(polls.clone())))
            .unwrap();
        for credential in credentials {
            request
                .headers_mut()
                .append("authorization", credential.parse().unwrap());
        }
        let usage = services
            .human_receipt_source
            .as_ref()
            .unwrap()
            .usage_for_test();
        let response = crate::http::grpc_gateway::human_projection_transport_for_test(services)
            .unwrap()
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.headers().get("grpc-status").unwrap(), "16");
        assert_eq!(polls.load(Ordering::Acquire), 0);
        assert_eq!(
            services
                .human_receipt_source
                .as_ref()
                .unwrap()
                .usage_for_test(),
            usage
        );
    }
}
#[derive(Clone)]
struct Peers;
fn authenticate<T>(q: &Request<T>) -> Result<(), Status> {
    if q.metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some(concat!(
            "Bearer ",
            "native-human-rpc-owned-caller-thirty-two-bytes"
        ))
    {
        return Err(Status::unauthenticated("fixture caller"));
    }
    Ok(())
}
#[tonic::async_trait]
impl guard_grpc::v1::network_server::Network for Peers {
    async fn check(
        &self,
        q: Request<guard_grpc::v1::NetworkRequest>,
    ) -> Result<Response<guard_grpc::v1::NetworkReply>, Status> {
        authenticate(&q)?;
        Ok(Response::new(guard_grpc::v1::NetworkReply {
            request_id: q.into_inner().request_id,
            revision: 3,
            verdict: 1,
            mode: 2,
            ttl_ms: 1000,
        }))
    }
}
#[tonic::async_trait]
impl hangang_route_grpc::v1::route_ownership_server::RouteOwnership for Peers {
    async fn observe(
        &self,
        q: Request<hangang_route_grpc::v1::RouteRequest>,
    ) -> Result<Response<hangang_route_grpc::v1::RouteReply>, Status> {
        authenticate(&q)?;
        let q = q.into_inner();
        if q.reference != vec![1; 32] || q.destination_sha256 != vec![0x12; 32] {
            return Err(Status::permission_denied("fixture route"));
        }
        Ok(Response::new(hangang_route_grpc::v1::RouteReply {
            request_id: q.request_id,
            route_id: "owned-route".into(),
            configuration_revision: 11,
            service: "orders".into(),
            audience: "orders-api".into(),
            resource: "db:orders".into(),
            action: "select".into(),
            client_ip: vec![192, 0, 2, 10],
            request_sha256: q.request_sha256,
            destination_sha256: q.destination_sha256,
            remaining_ms: 1000,
        }))
    }
}
fn private_file(path: impl AsRef<std::path::Path>) -> std::fs::File {
    let file = std::fs::File::create(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    file
}
fn authorized<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    request
}
async fn channel(address: String, ca: &[u8], cert: &[u8], key: &[u8]) -> tonic::transport::Channel {
    Endpoint::from_shared(address)
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap()
}
struct Owned {
    pum: tokio::process::Child,
    peers: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    hop: tokio::task::JoinHandle<anyhow::Result<()>>,
    stop: tokio::sync::watch::Sender<bool>,
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.peers.abort();
        self.hop.abort();
        let _ = self.pum.start_kill();
    }
}
async fn fresh_pair(
    sdk: &sdk::Client,
    permits: &mut pumgye_grpc::v1::human_observed_projection_permits_client::HumanObservedProjectionPermitsClient<tonic::transport::Channel>,
    cookie: &Secret,
    id: u64,
) -> (sdk::Observation, pumgye_grpc::v1::PermitValidationRequest) {
    use prost::Message;
    let prepared = sdk
        .prepare(
            &scope(),
            &hopae_grpc::request_binding_v2::Request {
                service: "orders",
                audience: "orders-api",
                route_id: "owned-route",
                route_revision: 11,
                destination_sha256: &[0x12; 32],
                method: "GET",
                target: "/data",
                body: b"body",
                bound_headers: &[],
            },
            headers(cookie),
        )
        .unwrap();
    let observation = sdk.issue(prepared).await.unwrap();
    let native = pumgye_grpc::v1::AuthenticatedResourceRequest {
        request_id: id,
        minimum_revision: 1,
        ip: vec![192, 0, 2, 10],
        resource: "db:orders".into(),
        action: "select".into(),
        receipt: observation.receipt().to_vec(),
        context: Some(
            prost::Message::decode(observation.context().encode_to_vec().as_slice()).unwrap(),
        ),
        request_sha256: observation.context().request_sha256.clone(),
        route: Some(pumgye_grpc::v1::NativeRouteReference {
            reference: vec![1; 32],
            destination_sha256: vec![0x12; 32],
        }),
    };
    let permit = permits
        .issue(authorized(native.clone()))
        .await
        .unwrap()
        .into_inner()
        .permit
        .unwrap();
    (
        observation,
        pumgye_grpc::v1::PermitValidationRequest {
            request_id: id + 100,
            request: Some(native),
            permit: Some(permit),
        },
    )
}
fn pair_ids(
    services: &crate::app::Services,
    request: &crate::auth_gateway::human_permission_live::Request,
) -> [String; 2] {
    let verifier = services.receipt_authority.lock().unwrap().verifier();
    [
        verifier
            .verify_observed_signature(
                &request.authentication_context().unwrap(),
                None,
                &request.native().receipt,
            )
            .unwrap(),
        verifier
            .verify_observed_signature(
                &request.permission_context().unwrap(),
                Some(&request.binding().unwrap()),
                &request.permit().receipt,
            )
            .unwrap(),
    ]
    .map(|checked| {
        format!(
            "projection_nonce_id:{}",
            data_encoding::HEXLOWER.encode(checked.replay_key())
        )
    })
}
fn pair_membership(services: &crate::app::Services, ids: &[String; 2]) -> [bool; 2] {
    std::array::from_fn(|i| {
        services
            .store
            .conn()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1)",
                [&ids[i]],
                |row| row.get(0),
            )
            .unwrap()
    })
}
#[tokio::test]
#[ignore = "requires explicit frozen PUBLIC Pum f6 binary; run separately"]
async fn native_human_projection_actual_sdk_pum_pair_replay_and_original_query() {
    use crate::auth_gateway::{
        projection, projection_resources, receipt::Purpose, receipt_authority, receipt_keys,
    };
    use prost::Message;
    let binary = std::env::var("HOPAE_H4_PUMGYE_BIN").expect("exact native Pum fixture required");
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&binary).unwrap())),
        "253e517847eaac50ced5237bb5672e588049018cccf9c2245c6f0228febdb4a4"
    );
    let f = Fx::new(None).await;
    let (cookie, view) = f.login().await;
    let (_bound, mut services) = services(&f).await;
    let root = tempfile::Builder::new()
        .prefix("hopae-human-h4-pair-fixture-")
        .tempdir()
        .unwrap()
        .keep();
    tls(root.as_path());
    let read = |name| std::fs::read(root.as_path().join(name)).unwrap();
    let ca = read("ca.pem");
    let cert = read("peer.pem");
    let key = read("peer.key");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop_address = format!("https://{}", listener.local_addr().unwrap());
    let reserve = || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let pum_address = reserve();
    let admin_address = reserve();
    let mut authority = receipt_authority::Authority::load(&f.store.conn(), 0).unwrap();
    authority
        .reconcile(
            &mut f.store.conn(),
            &[
                receipt_keys::Key {
                    issuer_ref: "native-human".into(),
                    purpose: Purpose::Authentication,
                    epoch: 1,
                    public_key: ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
                        .verifying_key()
                        .to_bytes(),
                },
                receipt_keys::Key {
                    issuer_ref: "pumgye".into(),
                    purpose: Purpose::Permit,
                    epoch: 1,
                    public_key: ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                        .verifying_key()
                        .to_bytes(),
                },
            ],
            "owned-H4-fixture",
            &|_| Ok(()),
        )
        .unwrap();
    services.receipt_authority = Arc::new(std::sync::Mutex::new(authority));
    services.human_receipt_source = Some(Arc::new(
        crate::auth_gateway::human_source::Source::new(
            services.human_owner.clone(),
            services.receipt_issuer.clone().unwrap(),
            services.receipt_authority.lock().unwrap().verifier(),
            &native(),
        )
        .unwrap(),
    ));
    let resources = projection_resources::Configuration {
        authority: projection_resources::Authority {
            address: format!("https://{pum_address}"),
            server_name: "localhost".into(),
            ca: root.as_path().join("ca.pem"),
            certificate: root.as_path().join("peer.pem"),
            key: root.as_path().join("peer.key"),
            token_env: "OWNED_PUM".into(),
        },
        workload_observed_scopes: vec![],
        human_observed_scopes: vec![projection_resources::HumanScope {
            service: "orders".into(),
            audience: "orders-api".into(),
            application: "app".into(),
            route: "owned-route".into(),
        }],
        observed_clock_rates: Some(projection_resources::ObservedClockRates {
            source_ppm: 500,
            receiver_ppm: 500,
        }),
        secrets: vec![projection_resources::SecretReference {
            reference: "owned:secret".into(),
            token_env: "OWNED_ORIGIN".into(),
        }],
    };
    services.projection_resources = Some(Arc::new(
        resources
            .prepare(&|name| match name {
                "OWNED_PUM" => Some(CALLER.into()),
                "OWNED_ORIGIN" => Some(ORIGIN.into()),
                _ => None,
            })
            .unwrap(),
    ));
    services
        .projection_authority
        .lock()
        .unwrap()
        .publish(
            &mut f.store.conn(),
            0,
            Some(projection::Configuration {
                revision: 1,
                plans: vec![projection::Plan {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                    minimum_aal: 1,
                    resource: "db:orders".into(),
                    action: "select".into(),
                    credential: projection::Credential::BearerReference {
                        secret_ref: "owned:secret".into(),
                    },
                }],
            }),
            "owned-H4-plan",
            &|_| Ok(()),
        )
        .unwrap();
    contract4_predecode(&services).await;
    let subject = f
        .store
        .admin_human_subject(
            "native-human".into(),
            view.session.user_id.as_str().into(),
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
        )
        .await
        .unwrap()
        .unwrap();
    let router = crate::app::build_routers(&services).unwrap().gateway;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let hop = tokio::spawn(crate::http::grpc_gateway::serve_with_receipts(
        listener,
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&cert, &key))
            .client_ca_root(Certificate::from_pem(&ca)),
        router,
        services.caller_keys.clone(),
        rx,
        Some(services.clone()),
    ));
    let peers_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peers_address = format!("https://{}", peers_listener.local_addr().unwrap());
    let peers = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(&cert, &key))
                    .client_ca_root(Certificate::from_pem(&ca)),
            )
            .unwrap()
            .add_service(guard_grpc::v1::network_server::NetworkServer::new(Peers))
            .add_service(
                hangang_route_grpc::v1::route_ownership_server::RouteOwnershipServer::new(Peers),
            )
            .serve_with_incoming(hangang_runtime::incoming(peers_listener)),
    );
    let write = |name: &str, value: serde_json::Value| {
        let p = root.as_path().join(name);
        std::fs::write(&p, value.to_string()).unwrap();
        p
    };
    let policy = write(
        "policy.json",
        serde_json::json!({"revision":1,"policy":{"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":1}},"users":{},"human_users":{subject:["reader"]},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}}}),
    );
    let public = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
            .verifying_key()
            .as_bytes(),
    );
    let trust = write(
        "trust.json",
        serde_json::json!({"entries":[{"issuer_ref":"native-human","key_epoch":1,"identity_epoch":"owned-human","service":"orders","audience":"orders-api","minimum_revision":7,"public_key":public}]}),
    );
    let transport = |address: &str| serde_json::json!({"address":address,"server_name":"localhost","ca":root.as_path().join("ca.pem"),"certificate":root.as_path().join("peer.pem"),"key":root.as_path().join("peer.key"),"token_env":"OWNED_PEER"});
    let mut human_transport = transport(&hop_address);
    human_transport["issuer_ref"] = serde_json::json!("native-human");
    human_transport["observed_clock_rates"] =
        serde_json::json!({"source_ppm":500,"receiver_ppm":500});
    let human = write(
        "human.json",
        serde_json::json!({"transport":human_transport,"minimum_source_revision":7,"minimum_application_generation":1,"minimum_key_registry_revision":1,"scopes":[{"service":"orders","audience":"orders-api","app_id":"app","route_id":"owned-route","route_revision":11,"destination_sha256":vec![0x12u8;32],"header_policy_revision":13,"header_names":[],"reserved_names":["x-owned-secret"]}]}),
    );
    let peers_file = write("peers.json", transport(&peers_address));
    let plan_file = write("plan.json", transport(&hop_address));
    let signer = write(
        "signer.json",
        serde_json::json!({"issuer_ref":"pumgye","key_epoch":1,"public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes()),"seed_env":"OWNED_SIGNER"}),
    );
    let pum = tokio::process::Command::new(binary)
        .args([
            "--listen",
            &admin_address.to_string(),
            "--grpc-listen",
            &pum_address.to_string(),
        ])
        .arg("--database")
        .arg(root.as_path().join("authority.sqlite3"))
        .arg("--policy")
        .arg(policy)
        .arg("--tls-cert")
        .arg(root.as_path().join("peer.pem"))
        .arg("--tls-key")
        .arg(root.as_path().join("peer.key"))
        .arg("--client-ca")
        .arg(root.as_path().join("ca.pem"))
        .arg("--human-observed-permits")
        .arg("--human-authentication-live")
        .arg(human)
        .arg("--authentication-trust")
        .arg(trust)
        .arg("--permit-key")
        .arg(signer)
        .arg("--network-live")
        .arg(&peers_file)
        .arg("--route-live")
        .arg(&peers_file)
        .arg("--projection-live")
        .arg(plan_file)
        .env(
            "PUMGYE_ADMIN_TOKEN",
            "owned-H4-admin-thirty-two-byte-fixture",
        )
        .env("PUMGYE_DECISION_TOKEN", CALLER)
        .env("OWNED_PEER", CALLER)
        .env("OWNED_SIGNER", STANDARD.encode([8; 32]))
        .stdout(std::process::Stdio::null())
        .stderr(private_file(root.as_path().join("pum.stderr")))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut owned = Owned {
        pum,
        peers,
        hop,
        stop,
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                owned.pum.try_wait().unwrap().is_none(),
                "native Pum exited before ready"
            );
            if tokio::net::TcpStream::connect(pum_address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let sdk = sdk::Client::new_human(
        sdk::EndpointConfig {
            address: &hop_address,
            server_name: "localhost",
            ca: &ca,
            certificate: &cert,
            private_key: &key,
            caller_key: CALLER,
        },
        sdk::HumanTrustPolicy {
            issuer_ref: "native-human".into(),
            key_epoch: 1,
            verifying_key: ed25519_dalek::SigningKey::from_bytes(&[0x45; 32]).verifying_key(),
            identity_authority: "owned-human".into(),
            scopes: vec![scope()],
            minimum_source_revision: 7,
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new([0x33; 16]).unwrap()),
        ClockRates::new(50, 50).unwrap(),
        sdk::Limits {
            concurrent: 8,
            timeout: Duration::from_millis(400),
        },
    )
    .unwrap();
    let prepare = sdk
        .prepare(
            &scope(),
            &hopae_grpc::request_binding_v2::Request {
                service: "orders",
                audience: "orders-api",
                route_id: "owned-route",
                route_revision: 11,
                destination_sha256: &[0x12; 32],
                method: "GET",
                target: "/data",
                body: b"body",
                bound_headers: &[],
            },
            headers(&cookie),
        )
        .unwrap();
    let observation = sdk.issue(prepare).await.unwrap();
    let native = pumgye_grpc::v1::AuthenticatedResourceRequest {
        request_id: 19,
        minimum_revision: 1,
        ip: vec![192, 0, 2, 10],
        resource: "db:orders".into(),
        action: "select".into(),
        receipt: observation.receipt().to_vec(),
        context: Some(
            prost::Message::decode(observation.context().encode_to_vec().as_slice()).unwrap(),
        ),
        request_sha256: observation.context().request_sha256.clone(),
        route: Some(pumgye_grpc::v1::NativeRouteReference {
            reference: vec![1; 32],
            destination_sha256: vec![0x12; 32],
        }),
    };
    let mut permits=pumgye_grpc::v1::human_observed_projection_permits_client::HumanObservedProjectionPermitsClient::new(
        channel(format!("https://{pum_address}"),&ca,&cert,&key).await);
    let permit = permits
        .issue(authorized(native.clone()))
        .await
        .unwrap()
        .into_inner()
        .permit
        .unwrap();
    let query = pumgye_grpc::v1::PermitValidationRequest {
        request_id: 81,
        request: Some(native.clone()),
        permit: Some(permit.clone()),
    };
    let projection = v1::ProjectionRequest {
        request_id: 81,
        permission_contract: 4,
        permission_query: query.encode_to_vec(),
    };
    let mut output=v1::human_observed_credential_projection_client::HumanObservedCredentialProjectionClient::new(
        channel(hop_address.clone(),&ca,&cert,&key).await);
    let sibling_runtime = crate::auth_gateway::projection_human::Runtime::from_services(&services)
        .unwrap()
        .unwrap();
    let first = output
        .project(authorized(projection.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.header_name, "authorization");
    assert!(
        first.header_value == format!("Bearer {ORIGIN}").as_bytes(),
        "unexpected projected credential (redacted)"
    );
    assert_eq!(
        first.chain_sha256,
        Sha256::digest(&projection.permission_query).to_vec()
    );
    assert!(
        sdk.check(&observation, observation.request()).is_ok(),
        "auth expired before replay qualification"
    );
    permits
        .observe(authorized(query.clone()))
        .await
        .expect("permit/native prerequisites must still be current before replay");
    assert_eq!(
        output
            .project(authorized(projection))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    let sibling_request =
        crate::auth_gateway::human_permission_live::Request::decode_observed_query(
            &query.encode_to_vec(),
            query.request_id,
        )
        .unwrap();
    let sibling_admission = services
        .human_owner
        .admit(Duration::from_millis(300))
        .unwrap();
    let sibling_admission = services
        .human_owner
        .capture(sibling_admission, services.readiness.clone())
        .unwrap()
        .take(&services.human_owner)
        .unwrap();
    assert!(
        sibling_runtime
            .project(sibling_request, sibling_admission, Arc::new(|| Ok(())))
            .await
            .is_err(),
        "another runtime/endpoint must retain same canonical replay authority"
    );
    permits
        .observe(authorized(query))
        .await
        .expect("replay rejection must not merely be prerequisite expiry");
    assert!(sdk.check(&observation, observation.request()).is_ok());
    let runtime = crate::auth_gateway::projection_human::Runtime::from_services(&services)
        .unwrap()
        .unwrap();
    assert!(
        runtime.same_receiver_for_test(&sibling_runtime),
        "all actual Services runtimes share exact receiver Arc"
    );

    let query_admission = || {
        let admission = services
            .human_owner
            .admit(Duration::from_millis(80))
            .unwrap();
        services
            .human_owner
            .capture(admission, services.readiness.clone())
            .unwrap()
            .take(&services.human_owner)
            .unwrap()
    };
    let nonce_count = || -> u64 {
        services
            .store
            .conn()
            .query_row(
                "SELECT count(*) FROM meta WHERE key>=?1 AND key<?2",
                rusqlite::params!["projection_nonce_id:", "projection_nonce_id;"],
                |row| row.get(0),
            )
            .unwrap()
    };
    let (live_auth, late_query) = fresh_pair(&sdk, &mut permits, &cookie, 82).await;
    let parsed = crate::auth_gateway::human_permission_live::Request::decode_observed_query(
        &late_query.encode_to_vec(),
        late_query.request_id,
    )
    .unwrap();
    let before = nonce_count();
    runtime.delay_after_permission_for_test(100);
    assert!(
        runtime
            .project(parsed, query_admission(), Arc::new(|| Ok(())))
            .await
            .is_err()
    );
    assert_eq!(
        runtime.completed_permissions_for_test(),
        1,
        "must have received actual Pum observation before controlled delay"
    );
    assert_eq!(
        nonce_count(),
        before,
        "expired query must not consume either nonce"
    );
    assert!(
        sdk.check(&live_auth, live_auth.request()).is_ok(),
        "auth must outlive expired query"
    );
    permits
        .observe(authorized(late_query))
        .await
        .expect("native proof remains valid after query refusal");
    runtime.delay_after_permission_for_test(0);
    let (live_auth, late_reply) = fresh_pair(&sdk, &mut permits, &cookie, 83).await;
    let parsed = crate::auth_gateway::human_permission_live::Request::decode_observed_query(
        &late_reply.encode_to_vec(),
        late_reply.request_id,
    )
    .unwrap();
    let reply_pair_ids = pair_ids(&services, &parsed);
    let pair_present = || pair_membership(&services, &reply_pair_ids) == [true, true];
    assert_eq!(pair_membership(&services, &reply_pair_ids), [false, false]);
    let mut pending = runtime
        .project(parsed, query_admission(), Arc::new(|| Ok(())))
        .await
        .unwrap();
    assert!(
        pair_present(),
        "both exact canonical pair keys must be consumed"
    );
    pending.after_allocation_for_test(Box::new(|| std::thread::sleep(Duration::from_millis(100))));
    assert!(
        pending.into_reply(late_reply.request_id).await.is_err(),
        "final reply must charge original query through allocations and native SQL"
    );
    assert!(
        pair_present(),
        "postcommit expiry discards output; exact consumed pair remains burned"
    );
    assert!(
        sdk.check(&live_auth, live_auth.request()).is_ok(),
        "auth must outlive final reply query"
    );
    permits
        .observe(authorized(late_reply))
        .await
        .expect("native proof remains valid after reply refusal");
    let (cancel_auth, cancel_query) = fresh_pair(&sdk, &mut permits, &cookie, 85).await;
    let parsed = crate::auth_gateway::human_permission_live::Request::decode_observed_query(
        &cancel_query.encode_to_vec(),
        cancel_query.request_id,
    )
    .unwrap();
    let cancel_ids = pair_ids(&services, &parsed);
    assert_eq!(pair_membership(&services, &cancel_ids), [false, false]);
    let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let hook_entered = entered.clone();
    let hook_release = release.clone();
    runtime.after_receiver_for_test(Some(Arc::new(move || {
        hook_entered.fetch_add(1, Ordering::AcqRel);
        let cutoff = std::time::Instant::now() + Duration::from_millis(250);
        while !hook_release.load(Ordering::Acquire) && std::time::Instant::now() < cutoff {
            std::thread::yield_now();
        }
    })));
    let started = std::time::Instant::now();
    let admission = services
        .human_owner
        .admit(Duration::from_millis(300))
        .unwrap();
    let admission = services
        .human_owner
        .capture(admission, services.readiness.clone())
        .unwrap()
        .take(&services.human_owner)
        .unwrap();
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        task_runtime
            .project(parsed, admission, Arc::new(|| Ok(())))
            .await
    });
    tokio::time::timeout(Duration::from_millis(100), async {
        while entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        entered.load(Ordering::Acquire),
        1,
        "controlled postreceiver event actually executed"
    );
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    release.store(true, Ordering::Release);
    runtime.after_receiver_for_test(None);
    services
        .store
        .human_ledger(
            crate::store::Deadline(std::time::Instant::now() + Duration::from_secs(1)),
            |_| Ok(()),
        )
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "original query still within its time budget"
    );
    assert_eq!(
        pair_membership(&services, &cancel_ids),
        [false, false],
        "late cancellation must roll back both canonical keys"
    );
    assert!(sdk.check(&cancel_auth, cancel_auth.request()).is_ok());
    permits
        .observe(authorized(cancel_query.clone()))
        .await
        .expect("cancel proof native owners still live");
    let retry = output
        .project(authorized(v1::ProjectionRequest {
            request_id: cancel_query.request_id,
            permission_contract: 4,
            permission_query: cancel_query.encode_to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        retry.header_value == format!("Bearer {ORIGIN}").as_bytes(),
        "cancelled unconsumed pair retry credential mismatch (redacted)"
    );
    assert_eq!(pair_membership(&services, &cancel_ids), [true, true]);
    let (withdraw_auth, withdraw_query) = fresh_pair(&sdk, &mut permits, &cookie, 86).await;
    let parsed = crate::auth_gateway::human_permission_live::Request::decode_observed_query(
        &withdraw_query.encode_to_vec(),
        withdraw_query.request_id,
    )
    .unwrap();
    let withdraw_ids = pair_ids(&services, &parsed);
    let events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook_events = events.clone();
    let readiness = services.readiness.clone();
    runtime.after_receiver_for_test(Some(Arc::new(move || {
        hook_events.fetch_add(1, Ordering::AcqRel);
        readiness.set(false);
    })));
    let started = std::time::Instant::now();
    let admission = services
        .human_owner
        .admit(Duration::from_millis(300))
        .unwrap();
    let admission = services
        .human_owner
        .capture(admission, services.readiness.clone())
        .unwrap()
        .take(&services.human_owner)
        .unwrap();
    assert!(
        runtime
            .project(parsed, admission, Arc::new(|| Ok(())))
            .await
            .is_err()
    );
    assert_eq!(
        events.load(Ordering::Acquire),
        1,
        "late native withdrawal event actually executed"
    );
    assert!(started.elapsed() < Duration::from_millis(300));
    assert!(
        sdk.check(&withdraw_auth, withdraw_auth.request()).is_ok(),
        "signed auth budget still live despite native withdrawal"
    );
    assert_eq!(
        pair_membership(&services, &withdraw_ids),
        [false, false],
        "late readiness withdrawal rolls back both canonical keys"
    );
    services.readiness.set(true);
    runtime.after_receiver_for_test(None);
    assert!(
        sdk.refresh(withdraw_auth).await.is_err(),
        "restored readiness cannot revive retired record"
    );
    let elevated = f.elevate(&cookie).await;
    let (two, two_query) = fresh_pair(&sdk, &mut permits, &elevated, 84).await;
    assert_eq!(two.context().identity.as_ref().unwrap().aal, 2);
    let two_reply = output
        .project(authorized(v1::ProjectionRequest {
            request_id: two_query.request_id,
            permission_contract: 4,
            permission_query: two_query.encode_to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        two_reply.header_value == format!("Bearer {ORIGIN}").as_bytes(),
        "AAL2 credential mismatch (redacted)"
    );
    owned.pum.kill().await.unwrap();
    owned.pum.wait().await.unwrap();
    owned.stop.send(true).unwrap();
}
