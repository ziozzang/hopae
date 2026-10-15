//! Human-only fixed-owner authenticated time evidence. This API grants no permission,
//! credential or revocation lease. Native startup owns pins and clock-rate policy.
//! Native configuration owners must retire the old client before replacing its
//! configuration. Every authorization/output consumer must independently fence
//! its current owner state; neither a pin nor check() is a remote freshness lease.
use crate::{PrincipalKind, human_epoch, receipt, receipt_binding, receipt_time, v1};
use ed25519_dalek::VerifyingKey;
use hangang_runtime::time::{ExchangeSample, LocalDeadline, ReceiverClock, ReplayRetention};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tonic::{
    metadata::{Ascii, MetadataValue},
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
/// Compiled native configuration, never built from incoming receipt fields.
/// One policy/client serves dynamic subjects and source process domains.
/// These startup metadata and prepared requests grant no authentication or time.
/// Replace configuration only after retiring this exact client instance.
pub struct HumanTrustPolicy {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub verifying_key: VerifyingKey,
    pub identity_authority: String,
    pub scopes: Vec<HumanScope>,
    pub minimum_source_revision: u64,
    pub minimum_application_generation: u64,
    pub minimum_key_registry_revision: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct HumanScope {
    pub service: String,
    pub audience: String,
    pub app_id: String,
    pub route_id: String,
    pub route_revision: u64,
    pub destination_sha256: [u8; 32],
    pub header_policy_revision: u64,
    pub header_names: Vec<String>,
    pub reserved_names: Vec<String>,
}
impl HumanScope {
    /// Canonical public scope metadata only, not proof or permission.
    pub fn fingerprint(&self) -> Result<[u8; 32], Refused> {
        let names = self
            .header_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let reserved = self
            .reserved_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        crate::human_scope::fingerprint(crate::human_scope::Scope {
            service: &self.service,
            audience: &self.audience,
            app_id: &self.app_id,
            route_id: &self.route_id,
            route_revision: self.route_revision,
            destination_sha256: &self.destination_sha256,
            header_policy_revision: self.header_policy_revision,
            header_names: &names,
            reserved_names: &reserved,
        })
        .map_err(|_| Refused)
    }

    fn policy(&self) -> Result<crate::request_binding_v2::HeaderPolicy, Refused> {
        let names = self
            .header_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let reserved = self
            .reserved_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let p = crate::request_binding_v2::HeaderPolicy::new(
            self.header_policy_revision,
            &names,
            &reserved,
        )
        .map_err(|_| Refused)?;
        let slots = names
            .iter()
            .map(|n| crate::request_binding_v2::BoundHeader {
                name: n,
                value: None,
            })
            .collect::<Vec<_>>();
        crate::request_binding_v2::digest(
            &p,
            &crate::request_binding_v2::Request {
                service: &self.service,
                audience: &self.audience,
                route_id: &self.route_id,
                route_revision: self.route_revision,
                destination_sha256: &self.destination_sha256,
                method: "GET",
                target: "/",
                body: b"",
                bound_headers: &slots,
            },
        )
        .map_err(|_| Refused)?;
        if self.app_id.is_empty()
            || self.app_id.len() > 128
            || !self
                .app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(Refused);
        }
        Ok(p)
    }
}
impl HumanTrustPolicy {
    fn key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    fn validate(&self, c: &v1::AuthenticationReceiptContext) -> Result<(), Refused> {
        binding(c)?;
        let epoch = human_epoch::decode(&c.identity_authority_epoch).map_err(|_| Refused)?;
        let i = c.identity.as_ref().ok_or(Refused)?;
        let subject = i.subject_ref.strip_prefix("human1:").ok_or(Refused)?;
        if c.issuer_ref != self.issuer_ref
            || c.key_epoch != self.key_epoch
            || epoch.authority != self.identity_authority
            || epoch.source_scope_revision < self.minimum_source_revision
            || epoch.application_generation < self.minimum_application_generation
            || subject.len() != 64
            || !subject
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !self
                .scopes
                .iter()
                .any(|s| s.service == c.service && s.audience == c.audience)
        {
            return Err(Refused);
        }
        Ok(())
    }
}
/// Shared startup-only authenticated transport and operation bounds.
pub use crate::observed_client::{EndpointConfig, Limits};
/// Body-derived issuance preparation. Cannot be constructed from a digest.
/// Observation-only inputs cannot enter issuance:
/// ```compile_fail
/// use hopae_grpc::human_observed_client::{Client, ObservationRequest};
/// fn cannot_issue(client: &Client, request: ObservationRequest) {
///     let _ = client.issue(request);
/// }
/// ```
pub struct IssuePrepared {
    request: Arc<PreparedRequest>,
}
/// Untrusted context/proof preparation, usable only with independent ObserveTime.
pub struct ObservationRequest {
    request: Arc<PreparedRequest>,
    receipt: Vec<u8>,
}
/// Opaque immutable request, bound to its creating client instance.
pub struct PreparedRequest {
    owner: Arc<()>,
    context: v1::AuthenticationReceiptContext,
    issue: v1::HumanReceiptRequest,
    resolved: bool,
    expected_scope_sha256: Option<[u8; 32]>,
}
/// Signature and transport/time evidence only. No Clone, serde or permission API.
pub struct Observation {
    request: Arc<PreparedRequest>,
    receipt: Vec<u8>,
    evidence: receipt::SignatureEvidence,
    deadline: LocalDeadline,
    retention: ReplayRetention,
    registry_revision: u64,
    scope: Arc<HumanScope>,
    scope_sha256: [u8; 32],
}
impl Observation {
    /// Actual authenticated fixed source scope metadata, never a permission grant.
    pub fn scope(&self) -> &HumanScope {
        &self.scope
    }

    /// Authenticated registry generation associated with this observation.
    /// Metadata alone does not establish current admission.
    pub fn key_registry_revision(&self) -> u64 {
        self.registry_revision
    }

    /// Exact signed public proof for a downstream owner to verify independently.
    pub fn receipt(&self) -> &[u8] {
        &self.receipt
    }
    pub fn context(&self) -> &v1::AuthenticationReceiptContext {
        &self.request.context
    }
    pub fn evidence(&self) -> &receipt::SignatureEvidence {
        &self.evidence
    }
    pub fn request(&self) -> &Arc<PreparedRequest> {
        &self.request
    }
}
type CompiledScope = (Arc<HumanScope>, [u8; 32]);

pub struct Client {
    rpc: v1::human_authentication_receipts_client::HumanAuthenticationReceiptsClient<Channel>,
    credential: MetadataValue<Ascii>,
    trust: HumanTrustPolicy,
    policies: Vec<crate::request_binding_v2::HeaderPolicy>,
    scope_data: Vec<CompiledScope>,
    registry_floor: AtomicU64,
    clock: Arc<ReceiverClock>,
    rates: receipt_time::ClockRates,
    timeout: Duration,
    admission: Semaphore,
    sequence: AtomicU64,
    active: AtomicBool,
    owner: Arc<()>,
}
fn compile_scope_data(scopes: &[HumanScope]) -> Result<Vec<CompiledScope>, Refused> {
    let mut seen = std::collections::HashSet::with_capacity(scopes.len());
    scopes
        .iter()
        .map(|scope| {
            let hash = scope.fingerprint()?;
            if !seen.insert(hash) {
                return Err(Refused);
            }
            Ok((Arc::new(scope.clone()), hash))
        })
        .collect()
}
fn verification_headers(headers: &[v1::Header]) -> Result<(), Refused> {
    use tonic::codegen::http::{HeaderName, HeaderValue};
    if headers.len() > 64 {
        return Err(Refused);
    }
    let mut total = 0usize;
    for h in headers {
        if h.name.is_empty() || h.name.len() > 128 || h.value.len() > 16384 {
            return Err(Refused);
        }
        let name = HeaderName::from_bytes(h.name.as_bytes()).map_err(|_| Refused)?;
        if name == "x-hopae-gateway-key" {
            return Err(Refused);
        }
        HeaderValue::from_bytes(&h.value).map_err(|_| Refused)?;
        total = total
            .checked_add(6 + h.name.len() + h.value.len())
            .ok_or(Refused)?;
        if total > 65536 {
            return Err(Refused);
        }
    }
    Ok(())
}
fn binding(c: &v1::AuthenticationReceiptContext) -> Result<[u8; 32], Refused> {
    let i = c.identity.as_ref().ok_or(Refused)?;
    if i.kind != 1 || !matches!(i.aal, 1 | 2) {
        return Err(Refused);
    }
    receipt_binding::digest(
        &receipt_binding::Context {
            issuer_ref: &c.issuer_ref,
            key_epoch: c.key_epoch,
            identity_authority_epoch: &c.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &i.subject_ref,
                kind: PrincipalKind::Human,
                aal: i.aal as u8,
                revision: i.revision,
                credential_generation: i.credential_generation,
            },
            service: &c.service,
            audience: &c.audience,
            request_sha256: c
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        },
        None,
    )
    .map_err(|_| Refused)
}
impl Client {
    /// Permanently retire this client, including in-flight admission. This does
    /// not retire a shared clock or permit deletion of replay retention records.
    pub fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }
    fn clock_result<T>(
        &self,
        result: Result<T, hangang_runtime::time::TimeError>,
    ) -> Result<T, Refused> {
        result.map_err(|error| {
            use hangang_runtime::time::TimeError;
            // An ordinary proof expiry is request-local, never a client DoS.
            if matches!(
                error,
                TimeError::ClockRead
                    | TimeError::Overflow
                    | TimeError::UnsupportedClock
                    | TimeError::Retired
            ) {
                self.retire();
            }
            Refused
        })
    }
    fn current(&self) -> Result<(), Refused> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Refused)
        }
    }
    pub fn new_human(
        config: EndpointConfig<'_>,
        policy: HumanTrustPolicy,
        clock: Arc<ReceiverClock>,
        rates: receipt_time::ClockRates,
        limits: Limits,
    ) -> Result<Self, Refused> {
        let valid_revision = |v| (1..=9_007_199_254_740_991).contains(&v);
        if policy.verifying_key.is_weak()
            || !valid_revision(policy.key_epoch)
            || !valid_revision(policy.minimum_source_revision)
            || !valid_revision(policy.minimum_application_generation)
            || !valid_revision(policy.minimum_key_registry_revision)
            || policy.scopes.is_empty()
            || policy.scopes.len() > 128
        {
            return Err(Refused);
        }
        for scope in &policy.scopes {
            let c = v1::AuthenticationReceiptContext {
                issuer_ref: policy.issuer_ref.clone(),
                key_epoch: policy.key_epoch,
                identity_authority_epoch: human_epoch::encode(
                    &policy.identity_authority,
                    policy.minimum_source_revision,
                    policy.minimum_application_generation,
                    "11111111111111111111111111111111",
                )
                .map_err(|_| Refused)?,
                identity: Some(v1::ReceiptIdentity {
                    subject_ref: format!("human1:{}", "a".repeat(64)),
                    kind: 1,
                    aal: 1,
                    revision: policy.minimum_source_revision,
                    credential_generation: policy.minimum_source_revision,
                }),
                service: scope.service.clone(),
                audience: scope.audience.clone(),
                request_sha256: vec![1; 32],
            };
            binding(&c)?;
            scope.policy()?;
        }
        Self::connect(config, policy, clock, rates, limits)
    }
    fn connect(
        config: EndpointConfig<'_>,
        trust: HumanTrustPolicy,
        clock: Arc<ReceiverClock>,
        rates: receipt_time::ClockRates,
        limits: Limits,
    ) -> Result<Self, Refused> {
        let uri: tonic::codegen::http::Uri = config.address.parse().map_err(|_| Refused)?;
        if config.address.len() > 256
            || uri.scheme_str() != Some("https")
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || uri.port_u16() == Some(0)
            || config.server_name.is_empty()
            || config.server_name.len() > 253
            || !config
                .server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || [config.ca, config.certificate, config.private_key]
                .iter()
                .any(|b| b.is_empty() || b.len() > 128 * 1024)
            || !(32..=256).contains(&config.caller_key.len())
            || !config.caller_key.bytes().all(|b| b.is_ascii_graphic())
            || !(1..=1024).contains(&limits.concurrent)
            || limits.timeout < Duration::from_millis(1)
            || limits.timeout > Duration::from_secs(1)
        {
            return Err(Refused);
        }
        let floor = trust.minimum_key_registry_revision;
        let policies = trust
            .scopes
            .iter()
            .map(HumanScope::policy)
            .collect::<Result<Vec<_>, _>>()?;
        let scope_data = compile_scope_data(&trust.scopes)?;
        let mut credential: MetadataValue<Ascii> = format!("Bearer {}", config.caller_key)
            .parse()
            .map_err(|_| Refused)?;
        credential.set_sensitive(true);
        let tls = ClientTlsConfig::new()
            .domain_name(config.server_name)
            .ca_certificate(Certificate::from_pem(config.ca))
            .identity(Identity::from_pem(config.certificate, config.private_key));
        let channel = Endpoint::from_shared(config.address.to_owned())
            .map_err(|_| Refused)?
            .connect_timeout(limits.timeout)
            .timeout(limits.timeout)
            .tls_config(tls)
            .map_err(|_| Refused)?
            .connect_lazy();
        Ok(Self {
            rpc: v1::human_authentication_receipts_client::HumanAuthenticationReceiptsClient::new(
                channel,
            )
            .max_encoding_message_size(128 * 1024)
            .max_decoding_message_size(128 * 1024),
            credential,
            trust,
            policies,
            scope_data,
            registry_floor: AtomicU64::new(floor),
            clock,
            rates,
            timeout: limits.timeout,
            admission: Semaphore::new(limits.concurrent),
            sequence: AtomicU64::new(1),
            active: AtomicBool::new(true),
            owner: Arc::new(()),
        })
    }
    /// Prepare issuance from the actual complete final body under fixed native scope.
    pub fn prepare(
        &self,
        scope: &HumanScope,
        request: &crate::request_binding_v2::Request<'_>,
        headers: Vec<v1::Header>,
    ) -> Result<IssuePrepared, Refused> {
        self.current()?;
        if !self.trust.scopes.contains(scope)
            || request.service != scope.service
            || request.audience != scope.audience
            || request.route_id != scope.route_id
            || request.route_revision != scope.route_revision
            || request.destination_sha256 != &scope.destination_sha256
        {
            return Err(Refused);
        }
        let index = self
            .trust
            .scopes
            .iter()
            .position(|s| s == scope)
            .ok_or(Refused)?;
        let actual = crate::request_binding_v2::bind_actual(&self.policies[index], request)
            .map_err(|_| Refused)?;
        verification_headers(&headers)?;
        let context = v1::AuthenticationReceiptContext {
            service: scope.service.clone(),
            audience: scope.audience.clone(),
            request_sha256: actual.request_sha256().to_vec(),
            ..Default::default()
        };
        let issue = v1::HumanReceiptRequest {
            verification: Some(v1::VerifyRequest {
                request_id: 0,
                headers,
            }),
            service: scope.service.clone(),
            audience: scope.audience.clone(),
            final_request: Some(v1::HumanFinalRequest {
                binding_contract: 2,
                method: request.method.into(),
                target: request.target.into(),
                entity_sha256: actual.body_sha256().to_vec(),
                entity_length: actual.body_length(),
                route_id: scope.route_id.clone(),
                route_revision: scope.route_revision,
                destination_sha256: scope.destination_sha256.to_vec(),
                header_policy_revision: scope.header_policy_revision,
                headers: request
                    .bound_headers
                    .iter()
                    .map(|h| v1::HumanBoundHeader {
                        name: h.name.into(),
                        present: h.value.is_some(),
                        value: h.value.unwrap_or_default().to_vec(),
                    })
                    .collect(),
            }),
        };
        Ok(IssuePrepared {
            request: Arc::new(PreparedRequest {
                owner: self.owner.clone(),
                context,
                issue,
                resolved: false,
                expected_scope_sha256: Some(self.scope_data[index].1),
            }),
        })
    }
    /// Metadata/signature input is not evidence. Only ObserveTime may create Observation.
    pub fn prepare_observation(
        &self,
        context: v1::AuthenticationReceiptContext,
        receipt: &[u8],
        expected_final_digest: [u8; 32],
    ) -> Result<ObservationRequest, Refused> {
        self.current()?;
        if context.request_sha256 != expected_final_digest || receipt.len() != receipt::LENGTH {
            return Err(Refused);
        }
        self.trust.validate(&context)?;
        Ok(ObservationRequest {
            request: Arc::new(PreparedRequest {
                owner: self.owner.clone(),
                context,
                resolved: true,
                expected_scope_sha256: None,
                issue: Default::default(),
            }),
            receipt: receipt.to_vec(),
        })
    }
    fn next_id(&self) -> Result<u64, Refused> {
        self.sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < 9_007_199_254_740_991).then_some(v + 1)
            })
            .map_err(|_| Refused)
    }
    fn rpc_request<T>(&self, body: T) -> tonic::Request<T> {
        let mut r = tonic::Request::new(body);
        r.metadata_mut()
            .insert("authorization", self.credential.clone());
        r.set_timeout(self.timeout);
        r
    }
    pub async fn issue(&self, prepared: IssuePrepared) -> Result<Observation, Refused> {
        let request = prepared.request;
        self.current()?;
        if !Arc::ptr_eq(&self.owner, &request.owner) {
            return Err(Refused);
        }
        let begun = self.clock_result(hangang_runtime::time::ElapsedStamp::now())?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let id = self.next_id()?;
        let mut body = request.issue.clone();
        body.verification.as_mut().ok_or(Refused)?.request_id = id;
        let start = self.clock_result(self.clock.begin_exchange())?;
        let response = tokio::time::timeout(
            self.timeout,
            self.rpc.clone().issue_observed(self.rpc_request(body)),
        )
        .await
        .map_err(|_| Refused)?
        .map_err(|_| Refused)?
        .into_inner();
        let exchange = self.clock_result(self.clock.finish_exchange(start))?;
        if exchange.elapsed_ms() > self.timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let reply = response.receipt.ok_or(Refused)?;
        let context = reply.context.ok_or(Refused)?;
        if reply.request_id != id
            || context.service != request.context.service
            || context.audience != request.context.audience
            || context.request_sha256 != request.context.request_sha256
            || (request.resolved && context != request.context)
        {
            return Err(Refused);
        }
        self.trust.validate(&context)?;
        let request = if request.resolved {
            request
        } else {
            Arc::new(PreparedRequest {
                owner: request.owner.clone(),
                context,
                issue: request.issue.clone(),
                resolved: true,
                expected_scope_sha256: request.expected_scope_sha256,
            })
        };
        let result = self.finish(
            request,
            reply.receipt,
            response.observation.ok_or(Refused)?,
            id,
            exchange,
        )?;
        if self.clock_result(begun.elapsed())? > self.timeout {
            return Err(Refused);
        }
        self.clock_result(result.deadline.check(&self.clock))?;
        self.check(&result, &result.request)?;
        Ok(result)
    }
    /// Independently observe an externally issued public proof at this fixed owner.
    /// The request must be prepared by this client with the exact final digest.
    /// This creates point-in-time evidence only; native active-owner fences remain
    /// mandatory before authorization/output. Refresh an existing observation to
    /// preserve its earlier admission deadline and longer replay retention.
    pub async fn observe(&self, prepared: ObservationRequest) -> Result<Observation, Refused> {
        let request = prepared.request;
        let receipt = prepared.receipt.as_slice();
        self.current()?;
        if !request.resolved
            || !Arc::ptr_eq(&self.owner, &request.owner)
            || receipt.len() != receipt::LENGTH
        {
            return Err(Refused);
        }
        let begun = self.clock_result(hangang_runtime::time::ElapsedStamp::now())?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let raw = receipt.to_vec();
        let evidence = receipt::verify_signature(
            self.trust.key(),
            &raw,
            receipt::Purpose::Authentication,
            &binding(&request.context)?,
        )
        .map_err(|_| Refused)?;
        let timeout = self
            .timeout
            .checked_sub(self.clock_result(begun.elapsed())?)
            .filter(|d| !d.is_zero())
            .ok_or(Refused)?;
        let id = self.next_id()?;
        let start = self.clock_result(self.clock.begin_exchange())?;
        let rpc = self.rpc_request(v1::HumanReceiptObservationRequest {
            request_id: id,
            context: Some(request.context.clone()),
            receipt: raw.clone(),
            request_sha256: request.context.request_sha256.clone(),
        });
        let report = tokio::time::timeout(timeout, self.rpc.clone().observe_time(rpc))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?
            .into_inner();
        let exchange = self.clock_result(self.clock.finish_exchange(start))?;
        if exchange.elapsed_ms() > timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let result = self.finish_verified(request, raw, evidence, report, id, exchange)?;
        if self.clock_result(begun.elapsed())? > self.timeout {
            return Err(Refused);
        }
        self.clock_result(result.deadline.check(&self.clock))?;
        self.check(&result, &result.request)?;
        Ok(result)
    }
    fn finish(
        &self,
        request: Arc<PreparedRequest>,
        raw: Vec<u8>,
        report: v1::HumanReceiptTimeReply,
        id: u64,
        exchange: ExchangeSample,
    ) -> Result<Observation, Refused> {
        let evidence = receipt::verify_signature(
            self.trust.key(),
            &raw,
            receipt::Purpose::Authentication,
            &binding(&request.context)?,
        )
        .map_err(|_| Refused)?;
        self.finish_verified(request, raw, evidence, report, id, exchange)
    }
    fn finish_verified(
        &self,
        request: Arc<PreparedRequest>,
        raw: Vec<u8>,
        evidence: receipt::SignatureEvidence,
        report: v1::HumanReceiptTimeReply,
        id: u64,
        exchange: ExchangeSample,
    ) -> Result<Observation, Refused> {
        let epoch =
            human_epoch::decode(&request.context.identity_authority_epoch).map_err(|_| Refused)?;
        if report.request_id != id
            || report.clock_domain != epoch.clock_domain
            || report.source_revision != epoch.source_scope_revision
            || report.application_generation != epoch.application_generation
            || !(1..=9_007_199_254_740_991).contains(&report.key_registry_revision)
            || report.key_registry_revision < self.registry_floor.load(Ordering::Acquire)
            || report.cache_ttl_ms != 0
        {
            return Err(Refused);
        }
        self.trust.validate(&request.context)?;
        let scope_sha256: [u8; 32] = report
            .scope_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?;
        if request
            .expected_scope_sha256
            .is_some_and(|expected| expected != scope_sha256)
        {
            return Err(Refused);
        }
        let scope = self
            .scope_data
            .iter()
            .find(|(s, sha)| {
                *sha == scope_sha256
                    && s.service == request.context.service
                    && s.audience == request.context.audience
            })
            .map(|(s, _)| s.clone())
            .ok_or(Refused)?;
        let bounds = receipt_time::Bounds::from_signature_with_rates(
            &evidence,
            &receipt_time::Report {
                owner_now_ms: report.owner_now_ms,
                remaining_ms: report.remaining_ms,
                receipt_sha256: report
                    .receipt_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| Refused)?,
            },
            &receipt_time::Exchange {
                before_ms: exchange.before_ticks(),
                after_ms: exchange.after_ticks(),
                elapsed_ms: exchange.elapsed_ms(),
            },
            &self.rates,
        )
        .map_err(|_| Refused)?;
        let (deadline, retention) = self.clock_result(
            exchange.bind_bounds(bounds.admit_until_ms(), bounds.retain_until_ms()),
        )?;
        // Ordinary requests only read the shared floor; reserve the cache-line
        // write for an actual authenticated registry advance.
        if report.key_registry_revision > self.registry_floor.load(Ordering::Acquire) {
            self.registry_floor
                .fetch_max(report.key_registry_revision, Ordering::AcqRel);
        }
        if report.key_registry_revision < self.registry_floor.load(Ordering::Acquire) {
            return Err(Refused);
        }
        Ok(Observation {
            request,
            receipt: raw,
            evidence,
            deadline,
            retention,
            registry_revision: report.key_registry_revision,
            scope,
            scope_sha256,
        })
    }
    pub fn check(
        &self,
        observation: &Observation,
        request: &Arc<PreparedRequest>,
    ) -> Result<Duration, Refused> {
        if !Arc::ptr_eq(&self.owner, &request.owner) || !Arc::ptr_eq(request, &observation.request)
        {
            return Err(Refused);
        }
        // Clock sampling may overlap retirement or a newer authenticated report.
        // Finish with native lifecycle/floor checks, not an external time read.
        let remaining = self.clock_result(observation.deadline.remaining(&self.clock))?;
        if observation.registry_revision < self.registry_floor.load(Ordering::Acquire) {
            return Err(Refused);
        }
        self.current()?;
        Ok(remaining)
    }
    /// Retention remains distinct from admission, including after clock retirement.
    pub fn retention_elapsed(&self, observation: &Observation) -> Result<bool, Refused> {
        if !Arc::ptr_eq(&self.owner, &observation.request.owner) {
            return Err(Refused);
        }
        self.clock_result(observation.retention.elapsed(&self.clock))
    }
    /// Consumes the old evidence; admission can only shrink and retention grow.
    pub async fn refresh(&self, previous: Observation) -> Result<Observation, Refused> {
        let remaining = self.check(&previous, &previous.request)?;
        let begun = self.clock_result(hangang_runtime::time::ElapsedStamp::now())?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let id = self.next_id()?;
        let start = self.clock_result(self.clock.begin_exchange())?;
        let timeout = self.timeout.min(remaining);
        let rpc = self.rpc_request(v1::HumanReceiptObservationRequest {
            request_id: id,
            context: Some(previous.request.context.clone()),
            receipt: previous.receipt.clone(),
            request_sha256: previous.request.context.request_sha256.clone(),
        });
        let report = tokio::time::timeout(timeout, self.rpc.clone().observe_time(rpc))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?
            .into_inner();
        let exchange = self.clock_result(self.clock.finish_exchange(start))?;
        if exchange.elapsed_ms() > timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let original_scope = previous.scope_sha256;
        let mut updated = self.finish(previous.request, previous.receipt, report, id, exchange)?;
        if updated.scope_sha256 != original_scope {
            return Err(Refused);
        }
        updated.deadline = updated
            .deadline
            .restrict(previous.deadline)
            .map_err(|_| Refused)?;
        updated.retention = updated
            .retention
            .extend(previous.retention)
            .map_err(|_| Refused)?;
        self.clock_result(updated.deadline.check(&self.clock))?;
        if self.clock_result(begun.elapsed())? > timeout {
            return Err(Refused);
        }
        self.check(&updated, &updated.request)?;
        Ok(updated)
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    #[test]
    fn startup_rejects_duplicate_canonical_scope_even_when_reserved_filters_differ() {
        let a = HumanScope {
            service: "orders".into(),
            audience: "api".into(),
            app_id: "app".into(),
            route_id: "route".into(),
            route_revision: 1,
            destination_sha256: [1; 32],
            header_policy_revision: 1,
            header_names: vec!["x-intent".into(), "content-type".into()],
            reserved_names: vec!["x-credential".into()],
        };
        assert!(compile_scope_data(std::slice::from_ref(&a)).is_ok());
        let mut b = a.clone();
        b.header_names.reverse();
        b.reserved_names = vec!["x-other-credential".into()];
        assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
        assert!(compile_scope_data(&[a.clone(), b.clone()]).is_err());
        b.route_id = "different".into();
        assert!(compile_scope_data(&[a, b]).is_ok());
    }
    fn h(name: &str, n: usize) -> v1::Header {
        v1::Header {
            name: name.into(),
            value: vec![b'a'; n],
        }
    }
    #[test]
    fn actual_native_header_count_value_and_framed_capacity_boundaries() {
        assert!(verification_headers(&vec![h("cookie", 0); 64]).is_ok());
        assert!(verification_headers(&vec![h("cookie", 0); 65]).is_err());
        assert!(verification_headers(&[h("cookie", 16384)]).is_ok());
        assert!(verification_headers(&[h("cookie", 16385)]).is_err());
        // Each record includes name plus6 framing bytes; total exactly65536.
        let mut exact = vec![h("x", 16377); 4];
        assert!(verification_headers(&exact).is_ok());
        exact[0].value.push(b'a');
        assert!(verification_headers(&exact).is_err());
        for name in ["x-hopae-gateway-key", "X-Hopae-Gateway-Key", "bad name", ""] {
            assert!(verification_headers(&[h(name, 1)]).is_err());
        }
        for value in ["a\r\nb", "a\0b", "a\u{7f}b"] {
            assert!(
                verification_headers(&[v1::Header {
                    name: "cookie".into(),
                    value: value.into()
                }])
                .is_err()
            );
        }
    }
}
