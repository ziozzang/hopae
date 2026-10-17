//! Fixed Workload-only input and native authenticated permit observation.
//! Unverified preparation is metadata; only a private actual owner RPC seals proof.
use super::receipt_keys::Refused;
use pumgye_grpc::v1::{AuthenticatedResourceRequest, ProjectionPermitReply};
use std::sync::Arc;
pub(crate) struct Request {
    inner: Arc<super::permission_live::Request>,
}
impl Request {
    pub(crate) fn decode_observed_query(
        bytes: &[u8],
        request_id: u64,
    ) -> Result<Arc<Self>, Refused> {
        let inner = super::permission_live::Request::decode_observed_query(bytes, request_id)
            .map_err(|_| Refused)?;
        let request = Arc::new(Self { inner });
        let a = request.authentication_context()?;
        let p = request.permission_context()?;
        for c in [&a, &p] {
            let epoch = hopae_grpc::workload_epoch::decode(c.identity_authority_epoch)
                .map_err(|_| Refused)?;
            let subject = c.identity.subject_ref.strip_prefix("s_").ok_or(Refused)?;
            if c.identity.revision != epoch.profile_revision
                || c.identity.credential_generation != epoch.profile_revision
                || subject.len() != 48
                || !subject
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Refused);
            }
        }
        super::projection_admission::validate_chain(&super::projection_admission::Input {
            authentication_context: &a,
            authentication_receipt: &request.native().receipt,
            permission_context: &p,
            permit: &request.binding()?,
            permission_receipt: &request.permit().receipt,
        })?;
        Ok(request)
    }
    pub(crate) fn observed_chain_sha256(&self) -> Result<[u8; 32], Refused> {
        self.inner.observed_chain_sha256()
    }
    pub(crate) fn authentication_context(
        &self,
    ) -> Result<super::receipt_binding::Context<'_>, super::receipt_keys::Refused> {
        use super::{
            PrincipalKind,
            receipt_binding::{Context, Identity},
            receipt_keys::Refused,
        };
        let context = self.inner.native().context.as_ref().ok_or(Refused)?;
        let identity = context.identity.as_ref().ok_or(Refused)?;
        if identity.kind != 3 || identity.aal != 0 {
            return Err(Refused);
        }
        Ok(Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: Identity {
                subject_ref: &identity.subject_ref,
                kind: PrincipalKind::Workload,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: context
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        })
    }
    pub(crate) fn permission_context(
        &self,
    ) -> Result<super::receipt_binding::Context<'_>, super::receipt_keys::Refused> {
        use super::{
            PrincipalKind,
            receipt_binding::{Context, Identity},
            receipt_keys::Refused,
        };
        let p = self.inner.permit().context.as_ref().ok_or(Refused)?;
        let i = p.identity.as_ref().ok_or(Refused)?;
        if i.kind != 3 || i.aal != 0 {
            return Err(Refused);
        }
        Ok(Context {
            issuer_ref: &p.issuer_ref,
            key_epoch: p.key_epoch,
            identity_authority_epoch: &p.identity_authority_epoch,
            identity: Identity {
                subject_ref: &i.subject_ref,
                kind: PrincipalKind::Workload,
                aal: 0,
                revision: i.revision,
                credential_generation: i.credential_generation,
            },
            service: &p.service,
            audience: &p.audience,
            request_sha256: p
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        })
    }
    pub(crate) fn binding(
        &self,
    ) -> Result<super::receipt_binding::Permit<'_>, super::receipt_keys::Refused> {
        use super::{receipt_binding::Permit, receipt_keys::Refused};
        let b = self.inner.permit().binding.as_ref().ok_or(Refused)?;
        Ok(Permit {
            authentication_receipt_sha256: b
                .authentication_receipt_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
            decision_ref: &b.decision_ref,
            resource: &b.resource,
            action: &b.action,
            authority_epoch: &b.authority_epoch,
            catalog_revision: b.catalog_revision,
            policy_revision: b.policy_revision,
            network_revision: b.network_revision,
            route_revision: b.route_revision,
            plan_revision: b.plan_revision,
        })
    }
    pub(crate) fn native(&self) -> &AuthenticatedResourceRequest {
        self.inner.native()
    }
    pub(crate) fn permit(&self) -> &ProjectionPermitReply {
        self.inner.permit()
    }
}

use pumgye_grpc::v1::PermitValidationRequest;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::Semaphore;
use tonic::metadata::MetadataValue;
const MAXIMUM: u64 = 9_007_199_254_740_991;
pub(crate) struct Client {
    channel: super::mtls_channel::ReloadingChannel,
    observed_rpc:pumgye_grpc::v1::workload_observed_projection_permits_client::WorkloadObservedProjectionPermitsClient<super::mtls_channel::ReloadingChannel>,
    credential:MetadataValue<tonic::metadata::Ascii>,
    admission:Semaphore,sequence:AtomicU64,owner:Arc<()>,
}
pub(crate) struct ObservedObservation {
    request: Arc<Request>,
    owner: Arc<()>,
    proof: super::receipt_replay::ObservedProof,
}
impl ObservedObservation {
    pub(crate) fn into_proof(
        self,
        request: &Arc<Request>,
        client: &Client,
        clock: &hangang_runtime::time::ReceiverClock,
    ) -> Result<super::receipt_replay::ObservedProof, Refused> {
        if !Arc::ptr_eq(&self.request, request) || !Arc::ptr_eq(&self.owner, &client.owner) {
            return Err(Refused);
        }
        self.proof.remaining(clock)?;
        Ok(self.proof)
    }
}
impl Client {
    pub(crate) fn prepare(
        address: &str,
        server_name: &str,
        ca: &[u8],
        certificate: &[u8],
        key: &[u8],
        token: &str,
    ) -> Result<Self, Refused> {
        let uri: tonic::codegen::http::Uri = address.parse().map_err(|_| Refused)?;
        if address.len() > 256
            || uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_none_or(|authority| authority.as_str().contains('@'))
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
            || uri.port_u16() == Some(0)
            || server_name.is_empty()
            || server_name.len() > 253
            || !server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || [ca, certificate, key]
                .iter()
                .any(|value| value.is_empty() || value.len() > 128 * 1024)
            || !(32..=256).contains(&token.len())
            || !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Refused);
        }
        let mut credential: MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {token}").parse().map_err(|_| Refused)?;
        credential.set_sensitive(true);
        let channel = super::mtls_channel::ReloadingChannel::new(
            address,
            server_name,
            super::mtls_channel::channel(address, server_name, ca, certificate, key)
                .map_err(|_| Refused)?,
        );
        Ok(Self {
            channel: channel.clone(),
            observed_rpc: pumgye_grpc::v1::workload_observed_projection_permits_client::WorkloadObservedProjectionPermitsClient::new(channel.clone()).max_encoding_message_size(8192).max_decoding_message_size(1024),
            credential,
            admission: Semaphore::new(128),
            sequence: AtomicU64::new(1),
            owner: Arc::new(()),
        })
    }
    pub(crate) async fn observe(
        &self,
        request: Arc<Request>,
        verifier: &super::receipt_authority::Verifier,
        clock: &hangang_runtime::time::ReceiverClock,
        rates: &hopae_grpc::receipt_time::ClockRates,
    ) -> Result<ObservedObservation, super::receipt_keys::Refused> {
        use super::receipt_keys::Refused;
        let _admission = self.admission.try_acquire().map_err(|_| Refused)?;
        let context = request.permission_context()?;
        let binding = request.binding()?;
        let checked = verifier.verify_observed_signature(
            &context,
            Some(&binding),
            &request.permit().receipt,
        )?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < MAXIMUM).then(|| v + 1)
            })
            .map_err(|_| Refused)?;
        let start = clock.begin_exchange().map_err(|_| Refused)?;
        let mut rpc = tonic::Request::new(PermitValidationRequest {
            request_id,
            request: Some(request.native().clone()),
            permit: Some(request.permit().clone()),
        });
        rpc.metadata_mut()
            .insert("authorization", self.credential.clone());
        rpc.set_timeout(Duration::from_secs(1));
        let reply = tokio::time::timeout(
            Duration::from_secs(1),
            self.observed_rpc.clone().observe(rpc),
        )
        .await
        .map_err(|_| Refused)?
        .map_err(|_| Refused)?
        .into_inner();
        let exchange = clock.finish_exchange(start).map_err(|_| Refused)?;
        let signed_remaining = checked
            .evidence()
            .claims()
            .expires_ms
            .checked_sub(reply.owner_now_ms)
            .ok_or(Refused)?;
        let domain = reply
            .clock_domain
            .strip_prefix("pobs1:")
            .and_then(|v| v.split_once(':'))
            .ok_or(Refused)?;
        if domain.0.len() != 32
            || !domain
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || domain.0.bytes().all(|b| b == b'0')
            || domain.1.is_empty()
            || domain.1.len() > 64
            || !domain
                .1
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || reply.request_id != request_id
            || reply.cache_ttl_ms != 0
            || reply.clock_domain != binding.authority_epoch
            || reply.receipt_sha256.as_slice() != checked.evidence().sha256()
            || u64::from(reply.proof_remaining_ms) != signed_remaining
            || reply.policy_revision != binding.policy_revision
            || reply.network_revision != binding.network_revision
            || reply.route_revision != binding.route_revision
            || reply.plan_revision != binding.plan_revision
        {
            return Err(Refused);
        }
        let proof = super::receipt_replay::ObservedProof::from_owner_report(
            checked,
            reply.clock_domain,
            &hopae_grpc::receipt_time::Report {
                owner_now_ms: reply.owner_now_ms,
                remaining_ms: reply.remaining_ms,
                receipt_sha256: reply
                    .receipt_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| Refused)?,
            },
            exchange,
            rates,
        )?;
        Ok(ObservedObservation {
            request,
            owner: self.owner.clone(),
            proof,
        })
    }
}

impl Client {
    /// Use new mTLS material for every later call ([`crate::reload`]).
    pub(crate) fn reload_tls(
        &self,
        ca: &[u8],
        certificate: &[u8],
        key: &[u8],
    ) -> Result<(), Refused> {
        if [ca, certificate, key]
            .iter()
            .any(|value| value.is_empty() || value.len() > 128 * 1024)
        {
            return Err(Refused);
        }
        self.channel
            .replace(ca, certificate, key)
            .map_err(|_| Refused)
    }
}
