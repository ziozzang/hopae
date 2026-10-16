//! WebAuthn credentials, ceremony state and recovery codes (ADR-0017).
//!
//! Every mutation re-checks the acting portal session inside its write
//! transaction (live handle, unchanged credential generation, factors and
//! authorization version) and evaluates the factor-management freshness rule
//! against the values it just re-checked. Callers still verify the WebAuthn
//! response, the TOTP code or the recovery code before calling.

use async_trait::async_trait;

use crate::crypto::{Digest, Timestamp};
use crate::event::types::Event;
use crate::identity::types::UserId;

use super::{FactorActor, HandleRow, HandoffCodeRow, StoreResult};

/// Conflict messages a caller may map to a specific page (all other
/// conflicts are a generic refusal).
pub mod refusal {
    /// The removal would leave the user without an active second factor.
    pub const LAST_FACTOR: &str = "last second factor";
    /// The action needs a second factor (or, without one, a fresh sign-in) at most five minutes old.
    pub const VERIFICATION_REQUIRED: &str = "recent verification required";
    /// The credential id is already registered (to anyone).
    pub const DUPLICATE_CREDENTIAL: &str = "credential already registered";
    /// The user holds the maximum number of active passkeys.
    pub const PASSKEY_CAPACITY: &str = "passkey capacity";
    /// The ceremony row is unknown, consumed, expired or bound elsewhere.
    pub const CEREMONY_UNAVAILABLE: &str = "ceremony unavailable";
    /// The stored counter already moved past the asserted one (same user, out-of-order tabs).
    pub const COUNTER_STALE: &str = "counter stale";
}

/// Most active passkeys per user.
pub const MAX_PASSKEYS: i64 = 20;
/// Most live (unconsumed, unexpired) ceremony rows per session.
pub const MAX_LIVE_CEREMONIES: i64 = 8;
/// Recovery codes per set.
pub const RECOVERY_CODES_PER_SET: usize = 10;
/// The factor-management freshness window (ADR-0017 decision 10).
pub const MANAGEMENT_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyPurpose {
    Register,
    Verify,
    StepUp,
}

impl CeremonyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            CeremonyPurpose::Register => "register",
            CeremonyPurpose::Verify => "verify",
            CeremonyPurpose::StepUp => "stepup",
        }
    }
}

/// Recorded assurance class of a credential (ADR-0017 decision 7). Never emitted as an AAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assurance {
    Aal2,
    Aal3,
}

impl Assurance {
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Aal2 => "aal2",
            Assurance::Aal3 => "aal3",
        }
    }
    pub fn parse(s: &str) -> Option<Assurance> {
        match s {
            "aal2" => Some(Assurance::Aal2),
            "aal3" => Some(Assurance::Aal3),
            _ => None,
        }
    }
}

/// A ceremony to persist. The digest is SHA-256 of the bearer the form carries.
pub struct NewCeremony {
    pub actor: FactorActor,
    pub purpose: CeremonyPurpose,
    pub digest: Digest,
    pub portal_binding: Digest,
    /// The step-up transaction digest (`StepUp` only).
    pub transaction: Option<Digest>,
    /// Serialized `webauthn-rs` state.
    pub state: String,
    pub expires_at: Timestamp,
}

/// A live ceremony row, read back for verification.
#[derive(Clone, Debug)]
pub struct CeremonyRecord {
    pub purpose: CeremonyPurpose,
    pub user_id: UserId,
    pub session_id: crate::session::types::SessionId,
    pub handle_sha256: Digest,
    pub portal_bind_sha256: Digest,
    pub transaction: Option<Digest>,
    pub credential_generation: u64,
    pub state: String,
    pub expires_at: Timestamp,
}

/// One stored credential (never carries a private key; the public key is in `passkey`).
#[derive(Clone, Debug)]
pub struct PasskeyRecord {
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub label: String,
    /// Serialized `webauthn-rs` credential.
    pub passkey: String,
    pub aaguid: Option<[u8; 16]>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub attestation_format: String,
    pub attested: bool,
    pub assurance: Assurance,
    pub sign_count: u32,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub revision: u64,
}

/// What the security pages show about a user.
#[derive(Clone, Debug, Default)]
pub struct FactorSummary {
    /// Active passkeys, oldest first.
    pub passkeys: Vec<PasskeyRecord>,
    pub totp_active: bool,
    pub recovery_unused: u32,
    pub recovery_generated_at: Option<Timestamp>,
    pub recovery_required_at: Option<Timestamp>,
}

impl FactorSummary {
    /// Active second factors (recovery codes do not count).
    pub fn second_factors(&self) -> usize {
        self.passkeys.len() + usize::from(self.totp_active)
    }
}

/// Register a verified credential and consume its ceremony.
pub struct RegisterPasskey {
    pub actor: FactorActor,
    pub ceremony: Digest,
    pub portal_binding: Digest,
    pub record: PasskeyRecord,
    pub events: Vec<Event>,
}

/// The verified use of a credential: the updated serialized credential and flags.
#[derive(Clone, Debug)]
pub struct PasskeyUse {
    pub credential_id: Vec<u8>,
    pub passkey: String,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// The class this assertion satisfied (`Aal3` only when the credential and the flags qualify).
    pub assurance: Assurance,
}

/// Application step-up completed with a passkey (ADR-0008 elevation shape).
pub struct WebauthnElevation {
    pub actor: FactorActor,
    pub ceremony: Digest,
    pub portal_binding: Digest,
    pub transaction: Digest,
    pub config_generation: u64,
    pub used: PasskeyUse,
    pub portal_handle: HandleRow,
    pub handoff: HandoffCodeRow,
    pub events: Vec<Event>,
}

/// Proof for the portal security confirmation.
pub enum PortalProof {
    Passkey {
        ceremony: Digest,
        used: PasskeyUse,
    },
    Totp {
        enrollment: String,
        revision: u64,
        counter: u64,
    },
    Recovery {
        lookup: String,
    },
}

/// Portal-only elevation: rotate the session's handles and reissue the portal handle.
pub struct PortalElevation {
    pub actor: FactorActor,
    pub portal_binding: Digest,
    pub proof: PortalProof,
    pub portal_handle: HandleRow,
    pub events: Vec<Event>,
}

/// What an administrator reset removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FactorResetReport {
    pub passkeys: u32,
    pub totp: u32,
    pub recovery_codes: u32,
    pub sessions: u32,
}

#[async_trait]
pub trait Passkeys: Send + Sync {
    /// The user's WebAuthn user handle, set to `candidate` when absent.
    async fn passkey_user_handle(
        &self,
        user: &UserId,
        candidate: [u8; 16],
    ) -> StoreResult<[u8; 16]>;
    async fn factor_summary(&self, user: &UserId) -> StoreResult<FactorSummary>;
    /// Persist a ceremony for the acting session (capped per session; a step-up
    /// ceremony requires a live step-up transaction of that session).
    async fn begin_ceremony(&self, ceremony: NewCeremony) -> StoreResult<()>;
    /// A live ceremony row.
    async fn ceremony(&self, digest: &Digest) -> StoreResult<Option<CeremonyRecord>>;
    /// Consume a ceremony after a failed attempt and record the failure.
    async fn fail_ceremony(&self, digest: &Digest, events: Vec<Event>) -> StoreResult<()>;
    async fn register_passkey(&self, request: RegisterPasskey) -> StoreResult<()>;
    async fn elevate_webauthn(&self, request: WebauthnElevation) -> StoreResult<()>;
    async fn elevate_portal(&self, request: PortalElevation) -> StoreResult<()>;
    /// A signature-verified assertion showed a counter regression: consume the
    /// ceremony, revoke the credential and end the sessions it elevated.
    async fn passkey_clone_detected(
        &self,
        ceremony: &Digest,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<()>;
    async fn rename_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        label: String,
        events: Vec<Event>,
    ) -> StoreResult<bool>;
    async fn revoke_passkey(
        &self,
        actor: FactorActor,
        credential_id: &[u8],
        events: Vec<Event>,
    ) -> StoreResult<bool>;
    /// Replace the user's recovery codes (`(lookup, argon2id hash)` pairs).
    async fn replace_recovery_codes(
        &self,
        actor: FactorActor,
        batch: String,
        codes: Vec<(String, String)>,
        events: Vec<Event>,
    ) -> StoreResult<()>;
    /// The hash of an unused recovery code.
    async fn recovery_code_hash(&self, user: &UserId, lookup: &str) -> StoreResult<Option<String>>;
    /// Administrator reset: every factor revoked, every session ended.
    async fn reset_factors(
        &self,
        user: &UserId,
        request_id: &str,
        events: Vec<Event>,
    ) -> StoreResult<FactorResetReport>;
}
