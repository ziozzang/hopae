//! Fixed-owner authenticated time evidence. This API grants no permission,
//! credential or revocation lease. Native startup owns pins and clock-rate policy.
//! Native configuration owners must retire the old client before replacing its
//! configuration. Every authorization/output consumer must independently fence
//! its current owner state; neither a pin nor check() is a remote freshness lease.
use crate::{PrincipalKind, receipt, receipt_binding, receipt_time, service_epoch, v1};
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
/// Native configuration only; never deserialize this from an incoming request.
pub struct OwnerPin {
    /// Exact expected context; request_sha256 must be empty (set by prepare).
    pub context: v1::AuthenticationReceiptContext,
    pub verifying_key: VerifyingKey,
    pub key_registry_revision: u64,
}
pub struct EndpointConfig<'a> {
    pub address: &'a str,
    pub server_name: &'a str,
    pub ca: &'a [u8],
    pub certificate: &'a [u8],
    pub private_key: &'a [u8],
    pub caller_key: &'a str,
}
pub struct Limits {
    pub concurrent: usize,
    /// Whole operation budget, from 1 millisecond through 1 second.
    pub timeout: Duration,
}
/// Opaque immutable request, bound to its creating client instance.
pub struct PreparedRequest {
    owner: Arc<()>,
    context: v1::AuthenticationReceiptContext,
    issue: v1::ServiceReceiptRequest,
}
/// Signature and transport/time evidence only. No Clone, serde or permission API.
pub struct Observation {
    request: Arc<PreparedRequest>,
    receipt: Vec<u8>,
    evidence: receipt::SignatureEvidence,
    deadline: LocalDeadline,
    retention: ReplayRetention,
}
impl Observation {
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
pub struct Client {
    rpc: v1::authentication_receipts_client::AuthenticationReceiptsClient<Channel>,
    credential: MetadataValue<Ascii>,
    pin: OwnerPin,
    clock: Arc<ReceiverClock>,
    rates: receipt_time::ClockRates,
    timeout: Duration,
    admission: Semaphore,
    sequence: AtomicU64,
    active: AtomicBool,
    owner: Arc<()>,
}
fn binding(c: &v1::AuthenticationReceiptContext) -> Result<[u8; 32], Refused> {
    let i = c.identity.as_ref().ok_or(Refused)?;
    if i.kind != 2 || i.aal != 0 {
        return Err(Refused);
    }
    receipt_binding::digest(
        &receipt_binding::Context {
            issuer_ref: &c.issuer_ref,
            key_epoch: c.key_epoch,
            identity_authority_epoch: &c.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &i.subject_ref,
                kind: PrincipalKind::Service,
                aal: 0,
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
    fn current(&self) -> Result<(), Refused> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Refused)
        }
    }
    pub fn new(
        config: EndpointConfig<'_>,
        pin: OwnerPin,
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
            || !pin.context.request_sha256.is_empty()
            || !(1..=9_007_199_254_740_991).contains(&pin.key_registry_revision)
            || pin.verifying_key.is_weak()
        {
            return Err(Refused);
        }
        let epoch = service_epoch::decode_clock(&pin.context.identity_authority_epoch)
            .map_err(|_| Refused)?;
        if pin.context.identity.as_ref().is_none_or(|i| {
            i.revision != epoch.epoch.profile_revision
                || i.credential_generation != epoch.epoch.profile_revision
        }) {
            return Err(Refused);
        }
        let mut check = pin.context.clone();
        check.request_sha256 = vec![1; 32];
        binding(&check)?;
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
            rpc: v1::authentication_receipts_client::AuthenticationReceiptsClient::new(channel)
                .max_encoding_message_size(16384)
                .max_decoding_message_size(4096),
            credential,
            pin,
            clock,
            rates,
            timeout: limits.timeout,
            admission: Semaphore::new(limits.concurrent),
            sequence: AtomicU64::new(1),
            active: AtomicBool::new(true),
            owner: Arc::new(()),
        })
    }
    pub fn prepare(
        &self,
        request: &crate::request_binding::Request<'_>,
        headers: Vec<v1::Header>,
    ) -> Result<Arc<PreparedRequest>, Refused> {
        self.current()?;
        if request.service != self.pin.context.service
            || request.audience != self.pin.context.audience
            || headers.len() > 32
            || headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
                > 8192
            || headers
                .iter()
                .any(|h| h.name.is_empty() || h.name.len() > 128 || h.value.len() > 8192)
        {
            return Err(Refused);
        }
        let digest = crate::request_binding::digest(request).map_err(|_| Refused)?;
        let mut context = self.pin.context.clone();
        context.request_sha256 = digest.to_vec();
        binding(&context)?;
        Ok(Arc::new(PreparedRequest {
            owner: self.owner.clone(),
            context,
            issue: v1::ServiceReceiptRequest {
                verification: Some(v1::VerifyRequest {
                    request_id: 0,
                    headers,
                }),
                service: request.service.into(),
                audience: request.audience.into(),
                request_sha256: digest.to_vec(),
            },
        }))
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
    pub async fn issue(&self, request: Arc<PreparedRequest>) -> Result<Observation, Refused> {
        self.current()?;
        if !Arc::ptr_eq(&self.owner, &request.owner) {
            return Err(Refused);
        }
        let begun = hangang_runtime::time::ElapsedStamp::now().map_err(|_| Refused)?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let id = self.next_id()?;
        let mut body = request.issue.clone();
        body.verification.as_mut().ok_or(Refused)?.request_id = id;
        let start = self.clock.begin_exchange().map_err(|_| Refused)?;
        let response = tokio::time::timeout(
            self.timeout,
            self.rpc
                .clone()
                .issue_service_observed(self.rpc_request(body)),
        )
        .await
        .map_err(|_| Refused)?
        .map_err(|_| Refused)?
        .into_inner();
        let exchange = self.clock.finish_exchange(start).map_err(|_| Refused)?;
        if exchange.elapsed_ms() > self.timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let reply = response.receipt.ok_or(Refused)?;
        if reply.request_id != id || reply.context.as_ref() != Some(&request.context) {
            return Err(Refused);
        }
        let result = self.finish(
            request,
            reply.receipt,
            response.observation.ok_or(Refused)?,
            id,
            exchange,
        )?;
        if begun.elapsed().map_err(|_| Refused)? > self.timeout {
            return Err(Refused);
        }
        result.deadline.check(&self.clock).map_err(|_| Refused)?;
        self.current()?;
        Ok(result)
    }
    /// Independently observe an externally issued public proof at this fixed owner.
    /// The request must be prepared by this client with the exact final digest.
    /// This creates point-in-time evidence only; native active-owner fences remain
    /// mandatory before authorization/output. Refresh an existing observation to
    /// preserve its earlier admission deadline and longer replay retention.
    pub async fn observe(
        &self,
        request: Arc<PreparedRequest>,
        receipt: &[u8],
    ) -> Result<Observation, Refused> {
        self.current()?;
        if !Arc::ptr_eq(&self.owner, &request.owner) || receipt.len() != receipt::LENGTH {
            return Err(Refused);
        }
        let begun = hangang_runtime::time::ElapsedStamp::now().map_err(|_| Refused)?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let raw = receipt.to_vec();
        let evidence = receipt::verify_signature(
            &self.pin.verifying_key,
            &raw,
            receipt::Purpose::Authentication,
            &binding(&request.context)?,
        )
        .map_err(|_| Refused)?;
        let timeout = self
            .timeout
            .checked_sub(begun.elapsed().map_err(|_| Refused)?)
            .filter(|d| !d.is_zero())
            .ok_or(Refused)?;
        let id = self.next_id()?;
        let start = self.clock.begin_exchange().map_err(|_| Refused)?;
        let rpc = self.rpc_request(v1::ServiceReceiptValidationRequest {
            request_id: id,
            context: Some(request.context.clone()),
            receipt: raw.clone(),
            request_sha256: request.context.request_sha256.clone(),
        });
        let report = tokio::time::timeout(timeout, self.rpc.clone().observe_service_time(rpc))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?
            .into_inner();
        let exchange = self.clock.finish_exchange(start).map_err(|_| Refused)?;
        if exchange.elapsed_ms() > timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let result = self.finish_verified(request, raw, evidence, report, id, exchange)?;
        if begun.elapsed().map_err(|_| Refused)? > self.timeout {
            return Err(Refused);
        }
        result.deadline.check(&self.clock).map_err(|_| Refused)?;
        self.current()?;
        Ok(result)
    }
    fn finish(
        &self,
        request: Arc<PreparedRequest>,
        raw: Vec<u8>,
        report: v1::ServiceReceiptTimeReply,
        id: u64,
        exchange: ExchangeSample,
    ) -> Result<Observation, Refused> {
        let evidence = receipt::verify_signature(
            &self.pin.verifying_key,
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
        report: v1::ServiceReceiptTimeReply,
        id: u64,
        exchange: ExchangeSample,
    ) -> Result<Observation, Refused> {
        let epoch = service_epoch::decode_clock(&request.context.identity_authority_epoch)
            .map_err(|_| Refused)?;
        if report.request_id != id
            || report.clock_domain != epoch.clock_domain
            || report.profile_revision != epoch.epoch.profile_revision
            || report.application_generation != epoch.epoch.application_generation
            || report.key_registry_revision != self.pin.key_registry_revision
            || report.cache_ttl_ms != 0
        {
            return Err(Refused);
        }
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
        let (deadline, retention) = exchange
            .bind_bounds(bounds.admit_until_ms(), bounds.retain_until_ms())
            .map_err(|_| Refused)?;
        Ok(Observation {
            request,
            receipt: raw,
            evidence,
            deadline,
            retention,
        })
    }
    pub fn check(
        &self,
        observation: &Observation,
        request: &Arc<PreparedRequest>,
    ) -> Result<Duration, Refused> {
        self.current()?;
        if !Arc::ptr_eq(&self.owner, &request.owner) || !Arc::ptr_eq(request, &observation.request)
        {
            return Err(Refused);
        }
        observation
            .deadline
            .remaining(&self.clock)
            .map_err(|_| Refused)
    }
    /// Retention remains distinct from admission, including after clock retirement.
    pub fn retention_elapsed(&self, observation: &Observation) -> Result<bool, Refused> {
        if !Arc::ptr_eq(&self.owner, &observation.request.owner) {
            return Err(Refused);
        }
        observation
            .retention
            .elapsed(&self.clock)
            .map_err(|_| Refused)
    }
    /// Consumes the old evidence; admission can only shrink and retention grow.
    pub async fn refresh(&self, previous: Observation) -> Result<Observation, Refused> {
        let remaining = self.check(&previous, &previous.request)?;
        let begun = hangang_runtime::time::ElapsedStamp::now().map_err(|_| Refused)?;
        let _slot = self.admission.try_acquire().map_err(|_| Refused)?;
        let id = self.next_id()?;
        let start = self.clock.begin_exchange().map_err(|_| Refused)?;
        let timeout = self.timeout.min(remaining);
        let rpc = self.rpc_request(v1::ServiceReceiptValidationRequest {
            request_id: id,
            context: Some(previous.request.context.clone()),
            receipt: previous.receipt.clone(),
            request_sha256: previous.request.context.request_sha256.clone(),
        });
        let report = tokio::time::timeout(timeout, self.rpc.clone().observe_service_time(rpc))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?
            .into_inner();
        let exchange = self.clock.finish_exchange(start).map_err(|_| Refused)?;
        if exchange.elapsed_ms() > timeout.as_millis() as u64 {
            return Err(Refused);
        }
        let mut updated = self.finish(previous.request, previous.receipt, report, id, exchange)?;
        updated.deadline = updated
            .deadline
            .restrict(previous.deadline)
            .map_err(|_| Refused)?;
        updated.retention = updated
            .retention
            .extend(previous.retention)
            .map_err(|_| Refused)?;
        updated.deadline.check(&self.clock).map_err(|_| Refused)?;
        if begun.elapsed().map_err(|_| Refused)? > timeout {
            return Err(Refused);
        }
        self.current()?;
        Ok(updated)
    }
}
