//! WebAuthn relying party over `webauthn-rs` (ADR-0017).
//!
//! This module owns the cryptographic ceremony only: options, state,
//! verification, the assurance class and authenticator naming. Persistence,
//! session binding and freshness are the store's ([`crate::store::Passkeys`]);
//! transport (CSRF, `Origin`, cookies) is the portal's.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::{
    AttestationCaList, AttestationCaListBuilder, AttestationFormat, AttestationMetadata,
    AttestedPasskey, AttestedPasskeyRegistration, AuthenticationResult, CreationChallengeResponse,
    Credential, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::store::passkeys::Assurance;

/// The `webauthn` configuration object. Absent: passkeys are disabled.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// Relying-party ID; defaults to the portal host.
    #[serde(default)]
    pub rp_id: Option<String>,
    /// Name the authenticator shows; defaults to `Hopae`.
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(default)]
    pub high_assurance: Option<HighAssuranceConfiguration>,
    /// Passwordless sign-in with passkeys on the login page (ADR-0017 decision 16).
    #[serde(default)]
    pub passwordless: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighAssuranceConfiguration {
    pub attestation_ca_files: Vec<PathBuf>,
    pub aaguids: Vec<String>,
}

/// Most allowlisted AAGUIDs and CA files.
const MAX_HIGH_ASSURANCE: usize = 64;

impl Configuration {
    /// Structural validation (no file access): the problems, each a full sentence.
    pub fn validate(&self, portal_public_url: &str) -> Vec<String> {
        let mut errs = vec![];
        match effective_rp_id(self.rp_id.as_deref(), portal_public_url) {
            Ok(_) => {}
            Err(e) => errs.push(format!("webauthn.rp_id: {e}")),
        }
        if let Some(name) = &self.rp_name
            && (name.trim().is_empty()
                || name.chars().count() > 64
                || name.chars().any(char::is_control))
        {
            errs.push("webauthn.rp_name must be 1-64 printable characters".into());
        }
        if let Some(h) = &self.high_assurance {
            if h.attestation_ca_files.is_empty() || h.aaguids.is_empty() {
                errs.push("webauthn.high_assurance needs attestation_ca_files and aaguids".into());
            }
            if h.attestation_ca_files.len() > MAX_HIGH_ASSURANCE
                || h.aaguids.len() > MAX_HIGH_ASSURANCE
            {
                errs.push("webauthn.high_assurance: at most 64 CA files and 64 AAGUIDs".into());
            }
            if h.aaguids
                .iter()
                .any(|a| Uuid::parse_str(a).map_or(true, |u| u.is_nil()))
            {
                errs.push("webauthn.high_assurance.aaguids must be non-zero UUIDs".into());
            }
        }
        errs
    }
}

/// The RP ID: the portal host, or a parent domain of it on a label boundary.
pub fn effective_rp_id(
    configured: Option<&str>,
    portal_public_url: &str,
) -> Result<String, String> {
    let portal =
        Url::parse(portal_public_url).map_err(|_| "portal.public_url is not a URL".to_string())?;
    let host = match portal.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        _ => return Err("the portal host must be a domain name".into()),
    };
    let Some(rp) = configured else {
        return Ok(host);
    };
    let rp = rp.trim_end_matches('.').to_ascii_lowercase();
    if rp.is_empty() || !rp.contains('.') || rp.parse::<std::net::IpAddr>().is_ok() {
        return Err("must be a domain name with at least two labels".into());
    }
    if rp != host && !host.ends_with(&format!(".{rp}")) {
        return Err(format!(
            "must be the portal host or a parent domain of it ({host})"
        ));
    }
    Ok(rp)
}

/// Why a ceremony failed. Never carries client data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Malformed JSON or state.
    Malformed,
    /// Signature, challenge, origin, RP ID, user verification or policy.
    Rejected,
    /// High-assurance registration: attestation or AAGUID not allowed.
    NotAllowed,
    /// A signature-verified assertion whose counter did not advance.
    CounterRegression,
}

impl Failure {
    pub fn label(self) -> &'static str {
        match self {
            Failure::Malformed => "malformed",
            Failure::Rejected => "rejected",
            Failure::NotAllowed => "not_allowed",
            Failure::CounterRegression => "counter_regression",
        }
    }
}

#[derive(Serialize, Deserialize)]
enum RegistrationState {
    Passkey(PasskeyRegistration),
    Attested(AttestedPasskeyRegistration),
}

/// A verified registration, ready to store.
#[derive(Debug, Clone)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    /// Serialized `webauthn-rs` credential.
    pub credential: String,
    pub aaguid: Option<[u8; 16]>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub attestation_format: String,
    pub attested: bool,
    pub assurance: Assurance,
    /// Known authenticator name for the AAGUID, if any.
    pub authenticator_name: Option<&'static str>,
}

/// A verified assertion, ready to record.
#[derive(Debug, Clone)]
pub struct Asserted {
    pub credential_id: Vec<u8>,
    pub credential: String,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub assurance: Assurance,
}

/// A stored credential as the relying party needs it.
pub struct StoredCredential<'a> {
    pub credential: &'a str,
    pub assurance: Assurance,
}

struct HighAssurance {
    cas: AttestationCaList,
    aaguids: BTreeSet<Uuid>,
}

/// The compiled relying party.
pub struct RelyingParty {
    webauthn: Webauthn,
    rp_id: String,
    high: Option<HighAssurance>,
    passwordless: bool,
}

impl std::fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelyingParty")
            .field("rp_id", &self.rp_id)
            .field("high_assurance", &self.high.is_some())
            .finish()
    }
}

impl RelyingParty {
    /// Build from configuration; reads the high-assurance CA files.
    pub fn compile(cfg: &Configuration, portal_public_url: &str) -> Result<RelyingParty, String> {
        let errs = cfg.validate(portal_public_url);
        if let Some(first) = errs.into_iter().next() {
            return Err(first);
        }
        let rp_id = effective_rp_id(cfg.rp_id.as_deref(), portal_public_url)?;
        let portal = Url::parse(portal_public_url)
            .map_err(|_| "portal.public_url is not a URL".to_string())?;
        let origin = Url::parse(&portal.origin().ascii_serialization())
            .map_err(|_| "portal.public_url has no origin".to_string())?;
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|_| "webauthn: the RP ID does not match the portal origin".to_string())?
            .rp_name(cfg.rp_name.as_deref().unwrap_or("Hopae"))
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|_| "webauthn: invalid relying-party configuration".to_string())?;
        let high = cfg
            .high_assurance
            .as_ref()
            .map(|h| -> Result<HighAssurance, String> {
                let aaguids: BTreeSet<Uuid> = h
                    .aaguids
                    .iter()
                    .filter_map(|a| Uuid::parse_str(a).ok())
                    .collect();
                let mut builder = AttestationCaListBuilder::new();
                for file in &h.attestation_ca_files {
                    let pem = std::fs::read(file).map_err(|_| {
                        format!("webauthn.high_assurance: cannot read {}", file.display())
                    })?;
                    let certs = openssl::x509::X509::stack_from_pem(&pem)
                        .ok()
                        .filter(|c| !c.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "webauthn.high_assurance: {} holds no PEM certificate",
                                file.display()
                            )
                        })?;
                    for cert in certs {
                        for aaguid in &aaguids {
                            builder
                                .insert_device_x509(
                                    cert.clone(),
                                    *aaguid,
                                    "allowlisted".into(),
                                    BTreeMap::new(),
                                )
                                .map_err(|_| {
                                    "webauthn.high_assurance: invalid CA certificate".to_string()
                                })?;
                        }
                    }
                }
                Ok(HighAssurance {
                    cas: builder.build(),
                    aaguids,
                })
            })
            .transpose()?;
        Ok(RelyingParty {
            webauthn,
            rp_id,
            high,
            passwordless: cfg.passwordless,
        })
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Whether passwordless sign-in is offered.
    pub fn passwordless(&self) -> bool {
        self.passwordless
    }

    /// Registration options as the page receives them. With passwordless
    /// sign-in the credential is requested discoverable (`residentKey:
    /// preferred`) so it can later sign in without a username.
    pub fn registration_options_json(
        &self,
        options: &CreationChallengeResponse,
    ) -> Result<String, Failure> {
        let mut v = serde_json::to_value(options).map_err(|_| Failure::Malformed)?;
        if self.passwordless
            && let Some(sel) = v.pointer_mut("/publicKey/authenticatorSelection")
            && let Some(o) = sel.as_object_mut()
        {
            o.insert("residentKey".into(), "preferred".into());
        }
        serde_json::to_string(&v).map_err(|_| Failure::Malformed)
    }

    /// Whether the high-assurance (attested security key) registration exists.
    pub fn high_assurance(&self) -> bool {
        self.high.is_some()
    }

    /// Registration options and the state to persist. `exclude` lists the
    /// user's existing credentials so one authenticator is not added twice.
    pub fn start_registration(
        &self,
        user_handle: [u8; 16],
        user_name: &str,
        display_name: &str,
        exclude: Vec<Vec<u8>>,
        high_assurance: bool,
    ) -> Result<(CreationChallengeResponse, String), Failure> {
        let user = Uuid::from_bytes(user_handle);
        let exclude: Vec<CredentialID> = exclude.into_iter().map(CredentialID::from).collect();
        let exclude = (!exclude.is_empty()).then_some(exclude);
        let (options, state) = if high_assurance {
            let high = self.high.as_ref().ok_or(Failure::NotAllowed)?;
            let (o, s) = self
                .webauthn
                .start_attested_passkey_registration(
                    user,
                    user_name,
                    display_name,
                    exclude,
                    high.cas.clone(),
                    None,
                )
                .map_err(|_| Failure::Rejected)?;
            (o, RegistrationState::Attested(s))
        } else {
            let (o, s) = self
                .webauthn
                .start_passkey_registration(user, user_name, display_name, exclude)
                .map_err(|_| Failure::Rejected)?;
            (o, RegistrationState::Passkey(s))
        };
        let state = serde_json::to_string(&state).map_err(|_| Failure::Malformed)?;
        Ok((options, state))
    }

    /// Verify a registration response against its persisted state.
    pub fn finish_registration(&self, response: &str, state: &str) -> Result<Registered, Failure> {
        let response: RegisterPublicKeyCredential =
            serde_json::from_str(response).map_err(|_| Failure::Malformed)?;
        let state: RegistrationState =
            serde_json::from_str(state).map_err(|_| Failure::Malformed)?;
        let (credential, attested_aaguid) = match &state {
            RegistrationState::Passkey(s) => {
                let pk: Passkey = self
                    .webauthn
                    .finish_passkey_registration(&response, s)
                    .map_err(|_| Failure::Rejected)?;
                (Credential::from(pk), None)
            }
            RegistrationState::Attested(s) => {
                let high = self.high.as_ref().ok_or(Failure::NotAllowed)?;
                let apk: AttestedPasskey = self
                    .webauthn
                    .finish_attested_passkey_registration(&response, s)
                    .map_err(|e| match e {
                        WebauthnError::AttestationNotSupported
                        | WebauthnError::AttestationTrustFailure
                        | WebauthnError::AttestationChainNotTrusted(_)
                        | WebauthnError::AttestationUntrustedAaguid
                        | WebauthnError::MissingAttestationCaList => Failure::NotAllowed,
                        _ => Failure::Rejected,
                    })?;
                let aaguid = match apk.attestation().metadata {
                    AttestationMetadata::Packed { aaguid }
                    | AttestationMetadata::Tpm { aaguid, .. } => aaguid,
                    _ => return Err(Failure::NotAllowed),
                };
                if !high.aaguids.contains(&aaguid) {
                    return Err(Failure::NotAllowed);
                }
                (Credential::from(apk), Some(aaguid))
            }
        };
        if !credential.user_verified {
            return Err(Failure::Rejected);
        }
        let attested = attested_aaguid.is_some();
        let aaguid = attested_aaguid
            .map(|u| *u.as_bytes())
            .or_else(|| aaguid_of(response.response.attestation_object.as_ref()))
            .filter(|a| a != &[0; 16]);
        let assurance = if attested && !credential.backup_eligible && !credential.backup_state {
            Assurance::Aal3
        } else {
            Assurance::Aal2
        };
        if attested && assurance != Assurance::Aal3 {
            // A synchronizable credential can never be high assurance.
            return Err(Failure::NotAllowed);
        }
        let transports = credential
            .transports
            .as_ref()
            .map(|t| {
                t.iter()
                    .filter_map(|t| serde_json::to_value(t).ok())
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .filter(|s| s != "unknown")
                    .take(8)
                    .collect()
            })
            .unwrap_or_default();
        let format = attestation_format_name(&credential.attestation_format);
        Ok(Registered {
            credential_id: credential.cred_id.to_vec(),
            aaguid,
            transports,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            user_verified: credential.user_verified,
            attestation_format: format.into(),
            attested,
            assurance,
            authenticator_name: aaguid.and_then(|a| authenticator_name(&a)),
            credential: serde_json::to_string(&credential).map_err(|_| Failure::Malformed)?,
        })
    }

    /// Assertion options for the user's active credentials, and the state to persist.
    pub fn start_authentication(
        &self,
        stored: &[StoredCredential<'_>],
    ) -> Result<(RequestChallengeResponse, String), Failure> {
        let passkeys: Vec<Passkey> = stored
            .iter()
            .map(|s| serde_json::from_str::<Credential>(s.credential).map(Passkey::from))
            .collect::<Result<_, _>>()
            .map_err(|_| Failure::Malformed)?;
        if passkeys.is_empty() {
            return Err(Failure::Rejected);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| Failure::Rejected)?;
        Ok((
            options,
            serde_json::to_string(&state).map_err(|_| Failure::Malformed)?,
        ))
    }

    /// Options and state for a passwordless sign-in (ADR-0017 decision 16):
    /// no user is known, the authenticator offers its discoverable passkeys
    /// (conditional mediation or a modal prompt). User verification required.
    pub fn start_login(&self) -> Result<(RequestChallengeResponse, String), Failure> {
        let (mut options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| Failure::Rejected)?;
        // The page chooses the mediation (conditional autofill or a button).
        options.mediation = None;
        Ok((
            options,
            serde_json::to_string(&state).map_err(|_| Failure::Malformed)?,
        ))
    }

    /// The user handle and credential id a passwordless response names
    /// (unverified: only for looking up the candidate credentials).
    pub fn identify_login(response: &str) -> Option<([u8; 16], Vec<u8>)> {
        let r: PublicKeyCredential = serde_json::from_str(response).ok()?;
        let handle: [u8; 16] = r.response.user_handle.as_ref()?.as_ref().try_into().ok()?;
        Some((handle, r.raw_id.to_vec()))
    }

    /// Verify a passwordless assertion against the named user's credentials.
    pub fn finish_login(
        &self,
        response: &str,
        state: &str,
        stored: &[StoredCredential<'_>],
    ) -> Result<Asserted, Failure> {
        let parsed: PublicKeyCredential =
            serde_json::from_str(response).map_err(|_| Failure::Malformed)?;
        let state: DiscoverableAuthentication =
            serde_json::from_str(state).map_err(|_| Failure::Malformed)?;
        let creds: Vec<(Credential, Assurance)> = stored
            .iter()
            .map(|s| serde_json::from_str::<Credential>(s.credential).map(|c| (c, s.assurance)))
            .collect::<Result<_, _>>()
            .map_err(|_| Failure::Malformed)?;
        let keys: Vec<DiscoverableKey> = creds
            .iter()
            .map(|(c, _)| DiscoverableKey::from(Passkey::from(c.clone())))
            .collect();
        let result = self
            .webauthn
            .finish_discoverable_authentication(&parsed, state, &keys)
            .map_err(|e| match e {
                WebauthnError::CredentialPossibleCompromise => Failure::CounterRegression,
                _ => Failure::Rejected,
            })?;
        if !result.user_verified() {
            return Err(Failure::Rejected);
        }
        let id = result.cred_id().to_vec();
        let (credential, class) = creds
            .into_iter()
            .find(|(c, _)| c.cred_id.as_slice() == id.as_slice())
            .ok_or(Failure::Rejected)?;
        let mut passkey = Passkey::from(credential);
        passkey.update_credential(&result);
        let assurance =
            if class == Assurance::Aal3 && !result.backup_eligible() && !result.backup_state() {
                Assurance::Aal3
            } else {
                Assurance::Aal2
            };
        Ok(Asserted {
            credential_id: id,
            sign_count: result.counter(),
            backup_eligible: result.backup_eligible(),
            backup_state: result.backup_state(),
            user_verified: true,
            assurance,
            credential: serde_json::to_string(&Credential::from(passkey))
                .map_err(|_| Failure::Malformed)?,
        })
    }

    /// The credential id a response names, for a failure record (unverified).
    pub fn response_credential_id(response: &str) -> Option<Vec<u8>> {
        serde_json::from_str::<PublicKeyCredential>(response)
            .ok()
            .map(|r| r.raw_id.to_vec())
    }

    /// Verify an assertion. `stored` must hold the credentials the state was
    /// built from (their current rows); the class is re-derived per assertion.
    pub fn finish_authentication(
        &self,
        response: &str,
        state: &str,
        stored: &[StoredCredential<'_>],
    ) -> Result<Asserted, Failure> {
        let response: PublicKeyCredential =
            serde_json::from_str(response).map_err(|_| Failure::Malformed)?;
        let state: PasskeyAuthentication =
            serde_json::from_str(state).map_err(|_| Failure::Malformed)?;
        let result: AuthenticationResult = self
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .map_err(|e| match e {
                WebauthnError::CredentialPossibleCompromise => Failure::CounterRegression,
                _ => Failure::Rejected,
            })?;
        if !result.user_verified() {
            return Err(Failure::Rejected);
        }
        let id = result.cred_id().to_vec();
        let (credential, class) = stored
            .iter()
            .find_map(|s| {
                let c = serde_json::from_str::<Credential>(s.credential).ok()?;
                (c.cred_id.as_slice() == id.as_slice()).then_some((c, s.assurance))
            })
            .ok_or(Failure::Rejected)?;
        let mut passkey = Passkey::from(credential);
        passkey.update_credential(&result);
        let updated = Credential::from(passkey);
        let assurance =
            if class == Assurance::Aal3 && !result.backup_eligible() && !result.backup_state() {
                Assurance::Aal3
            } else {
                Assurance::Aal2
            };
        Ok(Asserted {
            credential_id: id,
            sign_count: result.counter(),
            backup_eligible: result.backup_eligible(),
            backup_state: result.backup_state(),
            user_verified: result.user_verified(),
            assurance,
            credential: serde_json::to_string(&updated).map_err(|_| Failure::Malformed)?,
        })
    }
}

fn attestation_format_name(f: &AttestationFormat) -> &'static str {
    match f {
        AttestationFormat::Packed => "packed",
        AttestationFormat::Tpm => "tpm",
        AttestationFormat::AndroidKey => "android-key",
        AttestationFormat::AndroidSafetyNet => "android-safetynet",
        AttestationFormat::FIDOU2F => "fido-u2f",
        AttestationFormat::AppleAnonymous => "apple",
        AttestationFormat::None => "none",
    }
}

/// The AAGUID in a verified attestation object's authenticator data
/// (rpIdHash 32 | flags 1 | signCount 4 | AAGUID 16 | ...). Display only:
/// without a verified attestation it is the authenticator's own claim.
fn aaguid_of(attestation_object: &[u8]) -> Option<[u8; 16]> {
    let value: serde_cbor_2::Value = serde_cbor_2::from_slice(attestation_object).ok()?;
    let serde_cbor_2::Value::Map(map) = value else {
        return None;
    };
    let auth = map.iter().find_map(|(k, v)| match (k, v) {
        (serde_cbor_2::Value::Text(k), serde_cbor_2::Value::Bytes(b)) if k == "authData" => Some(b),
        _ => None,
    })?;
    // The attested-credential-data flag (bit 6) must be set.
    if auth.len() < 53 || auth[32] & 0x40 == 0 {
        return None;
    }
    auth[37..53].try_into().ok()
}

/// Best-effort names of widely deployed authenticators and passkey providers,
/// by AAGUID. Cosmetic: used only as the default label, never for policy.
const KNOWN_AUTHENTICATORS: &[(&str, &str)] = &[
    (
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
        "Google Password Manager",
    ),
    ("adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac"),
    ("fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "iCloud Keychain"),
    (
        "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
        "iCloud Keychain (Managed)",
    ),
    ("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello"),
    ("9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "Windows Hello"),
    ("6028b017-b1d4-4c02-b4b3-afcdafc96bb2", "Windows Hello"),
    ("bada5566-a7aa-401f-bd96-45619a55120d", "1Password"),
    ("d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden"),
    ("531126d6-e717-415c-9320-3d9aa6981239", "Dashlane"),
    ("fdb141b2-5d84-443e-8a35-4698c205a502", "KeePassXC"),
    ("53414d53-554e-4700-0000-000000000000", "Samsung Pass"),
    ("50726f74-6f6e-5061-7373-50726f746f6e", "Proton Pass"),
    ("cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 Series"),
    ("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5 Series"),
    (
        "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
        "YubiKey 5 Series with NFC",
    ),
    (
        "2fc0579f-8113-47ea-b116-bb5a8db9202a",
        "YubiKey 5 Series with NFC",
    ),
    ("c5ef55ff-ad9a-4b9f-b580-adebafe026d0", "YubiKey 5Ci"),
    (
        "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
        "YubiKey 5 FIPS Series",
    ),
    (
        "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa",
        "Security Key NFC by Yubico",
    ),
    (
        "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3",
        "Google Titan Security Key",
    ),
];

pub fn authenticator_name(aaguid: &[u8; 16]) -> Option<&'static str> {
    let u = Uuid::from_bytes(*aaguid);
    KNOWN_AUTHENTICATORS
        .iter()
        .find(|(id, _)| Uuid::parse_str(id).is_ok_and(|k| k == u))
        .map(|(_, name)| *name)
}

#[cfg(test)]
#[path = "webauthn_tests.rs"]
mod tests;
