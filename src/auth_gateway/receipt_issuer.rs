//! Native session receipt signing. The verify engine seals original metadata;
//! caller claims, ordinary response headers and Lua are never signing inputs.
use super::{
    PrincipalKind,
    receipt::{self, Claims, Purpose},
    receipt_binding::{Context, Identity as BindingIdentity},
    receipt_keys::Refused,
};
use crate::{
    crypto::{Clock, Rng, Timestamp},
    verify::types::Identity,
};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

pub(crate) struct SessionSeal {
    digest: [u8; 32],
    verified_ms: i64,
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}
fn metadata(identity: &Identity, service: &str, verified_ms: i64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"hopae:native-session-receipt-seal:v1\0");
    for value in [
        service,
        identity.user_id.as_str(),
        identity.session_id.as_str(),
        identity.provider_id.as_str(),
    ] {
        field(&mut hash, value.as_bytes());
    }
    for value in [identity.auth_time.0, identity.expires_at.0, verified_ms] {
        field(&mut hash, &value.to_be_bytes());
    }
    for value in [
        identity.generations.user,
        identity.generations.session,
        identity.generations.config,
        identity.aal.as_i64() as u64,
    ] {
        field(&mut hash, &value.to_be_bytes());
    }
    hash.finalize().into()
}
impl SessionSeal {
    pub(crate) fn new(identity: &Identity, service: &str, verified: Timestamp) -> Self {
        Self {
            digest: metadata(identity, service, verified.0),
            verified_ms: verified.0,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Scope {
    pub service: String,
    pub audience: String,
}
#[derive(Clone, Debug)]
pub struct Configuration {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub identity_authority_epoch: String,
    pub public_key: [u8; 32],
    pub scopes: Vec<Scope>,
}
pub struct Request<'a> {
    pub service: &'a str,
    pub audience: &'a str,
    pub request_sha256: [u8; 32],
}
pub struct Issuer {
    config: Arc<Configuration>,
    signer: ed25519_dalek::SigningKey,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    observed_time: AtomicU64,
    scopes: std::collections::HashMap<String, std::collections::HashSet<String>>,
}
/// No Clone/Debug/serde: adapters must expose this only through the authenticated
/// receipt phase, never automatically through ordinary auth-response headers.
pub struct Issued {
    config: Arc<Configuration>,
    identity_epoch: String,
    subject: String,
    kind: PrincipalKind,
    aal: u8,
    revision: u64,
    credential_generation: u64,
    service: String,
    audience: String,
    request_sha256: [u8; 32],
    bytes: [u8; receipt::LENGTH],
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
impl Issuer {
    /// Seed is supplied by a native key-vault capability, with a pinned public key.
    /// Clock/RNG are native resources; production wiring must use the OS CSPRNG.
    pub fn new(
        config: Configuration,
        seed: Zeroizing<[u8; 32]>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, Refused> {
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        if !identifier(&config.issuer_ref)
            || !identifier(&config.identity_authority_epoch)
            || config.identity_authority_epoch.len() > 96
            || !(1..=9_007_199_254_740_991).contains(&config.key_epoch)
            || signer.verifying_key().is_weak()
            || signer.verifying_key().to_bytes() != config.public_key
        {
            return Err(Refused);
        }
        if config.scopes.is_empty() || config.scopes.len() > 128 {
            return Err(Refused);
        }
        let mut scopes: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for scope in &config.scopes {
            if !identifier(&scope.service)
                || !identifier(&scope.audience)
                || !scopes
                    .entry(scope.service.clone())
                    .or_default()
                    .insert(scope.audience.clone())
            {
                return Err(Refused);
            }
        }
        Ok(Self {
            config: Arc::new(config),
            signer,
            clock,
            rng,
            observed_time: AtomicU64::new(0),
            scopes,
        })
    }
    fn now(&self) -> Result<u64, Refused> {
        let now = u64::try_from(self.clock.now().0).map_err(|_| Refused)?;
        Ok(self.observed_time.fetch_max(now, Ordering::AcqRel).max(now))
    }
    /// Native guard must inspect current session/handle, user/provider/config and
    /// signer epoch both times. The seal prevents changing a prior native allow;
    /// it cannot replace live revocation or distributed authority fences.
    pub fn issue_session(
        &self,
        identity: &Identity,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        if !self
            .scopes
            .get(request.service)
            .is_some_and(|audiences| audiences.contains(request.audience))
        {
            return Err(Refused);
        }
        let seal = identity.receipt_seal.as_ref().ok_or(Refused)?;
        if seal.digest != metadata(identity, request.service, seal.verified_ms) {
            return Err(Refused);
        }
        let begun = std::time::Instant::now();
        let now = self.now()?;
        let verified = u64::try_from(seal.verified_ms).map_err(|_| Refused)?;
        let expires = u64::try_from(identity.expires_at.0)
            .map_err(|_| Refused)?
            .min(verified.checked_add(1000).ok_or(Refused)?)
            .min(now.saturating_add(1000));
        if now < verified || now >= expires {
            return Err(Refused);
        }
        guard()?;
        let issued = Issued {
            config: self.config.clone(),
            identity_epoch: format!(
                "{}:{}",
                self.config.identity_authority_epoch, identity.generations.config
            ),
            subject: identity.user_id.as_str().to_owned(),
            kind: PrincipalKind::Human,
            aal: identity.aal.as_i64() as u8,
            revision: identity.generations.user,
            credential_generation: identity.generations.session,
            service: request.service.to_owned(),
            audience: request.audience.to_owned(),
            request_sha256: request.request_sha256,
            bytes: [0; receipt::LENGTH],
        };
        if !(1..=9_007_199_254_740_991).contains(&identity.generations.config) {
            return Err(Refused);
        }
        self.sign_checked(issued, now, expires, begun, guard)
    }
    /// Only profile-owned Service evidence is supported here. Neither network
    /// evidence nor an arbitrary caller principal can manufacture Human/MFA.
    pub fn issue_service(
        &self,
        authentication: &super::authority::ServiceAuthentication,
        request: Request<'_>,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        let evidence = &authentication.evidence;
        if evidence.subject.kind != PrincipalKind::Service
            || evidence.service.as_deref() != Some(request.service)
            || !self
                .scopes
                .get(request.service)
                .is_some_and(|audiences| audiences.contains(request.audience))
        {
            return Err(Refused);
        }
        let begun = std::time::Instant::now();
        let now = self.now()?;
        let expires = evidence
            .expires_at
            .min(
                authentication
                    .verified_ms
                    .checked_add(1000)
                    .ok_or(Refused)?,
            )
            .min(now.saturating_add(1000));
        if now < authentication.verified_ms || now >= expires {
            return Err(Refused);
        }
        guard()?;
        let issued = Issued {
            config: self.config.clone(),
            identity_epoch: format!(
                "{}:service:{}",
                self.config.identity_authority_epoch, authentication.revision
            ),
            subject: super::stable_subject(&evidence.subject),
            kind: PrincipalKind::Service,
            aal: 0,
            revision: authentication.revision,
            credential_generation: authentication.revision,
            service: request.service.to_owned(),
            audience: request.audience.to_owned(),
            request_sha256: request.request_sha256,
            bytes: [0; receipt::LENGTH],
        };
        self.sign_checked(issued, now, expires, begun, guard)
    }
    fn sign_checked(
        &self,
        mut issued: Issued,
        now: u64,
        expires: u64,
        begun: std::time::Instant,
        guard: &dyn Fn() -> Result<(), Refused>,
    ) -> Result<Issued, Refused> {
        let binding =
            super::receipt_binding::digest(&issued.context(), None).map_err(|_| Refused)?;
        let mut nonce = [0; 32];
        self.rng.fill(&mut nonce);
        issued.bytes = receipt::sign(
            &self.signer,
            &Claims {
                purpose: Purpose::Authentication,
                issued_ms: now,
                expires_ms: expires,
                binding,
                nonce,
            },
        )
        .map_err(|_| Refused)?;
        guard()?;
        let final_now = self
            .now()?
            .max(now.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        self.observed_time.fetch_max(final_now, Ordering::AcqRel);
        if final_now >= expires {
            return Err(Refused);
        }
        Ok(issued)
    }
}
impl Issued {
    pub fn bytes(&self) -> &[u8; receipt::LENGTH] {
        &self.bytes
    }
    pub fn context(&self) -> Context<'_> {
        Context {
            issuer_ref: &self.config.issuer_ref,
            key_epoch: self.config.key_epoch,
            identity_authority_epoch: &self.identity_epoch,
            identity: BindingIdentity {
                subject_ref: &self.subject,
                kind: self.kind,
                aal: self.aal,
                revision: self.revision,
                credential_generation: self.credential_generation,
            },
            service: &self.service,
            audience: &self.audience,
            request_sha256: self.request_sha256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_gateway::{
        authority::Authority,
        receipt_keys::{Key, Registry},
        runtime,
    };
    fn config(relay_url: Option<String>) -> runtime::Config {
        let mut value = serde_json::json!({"authority_id":"owned","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"OWNED_NATIVE_KEY","subject":"worker","expires_at":350}],"networks":["203.0.113.0/24"]}]});
        if let Some(url) = relay_url {
            value["profiles"][0]["relay_token_prefix"] = serde_json::json!("partner:");
            value["profiles"][0]["api_relay"] = serde_json::json!({"url":url,"issuer":"https://partner.example.test","timeout_ms":500,"allow_private_endpoints":true});
        }
        serde_json::from_value(value).unwrap()
    }
    const TOKEN: &str = "owned-native-key-at-least-thirty-two-bytes";
    fn owner(db: &mut rusqlite::Connection, configuration: runtime::Config) -> Authority {
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            .unwrap();
        Authority::load(
            db,
            Some(configuration),
            &|_| Some(TOKEN.into()),
            &|_| Ok(()),
        )
        .unwrap()
    }
    fn issuer(clock: Arc<crate::crypto::TestClock>) -> Issuer {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        Issuer::new(
            Configuration {
                issuer_ref: "owned-hopae".into(),
                key_epoch: 1,
                identity_authority_epoch: "identity-1".into(),
                public_key: signer.verifying_key().to_bytes(),
                scopes: vec![Scope {
                    service: "orders".into(),
                    audience: "orders-api".into(),
                }],
            },
            Zeroizing::new([7; 32]),
            clock,
            Arc::new(crate::crypto::OsRng),
        )
        .unwrap()
    }
    fn request() -> Request<'static> {
        Request {
            service: "orders",
            audience: "orders-api",
            request_sha256: [4; 32],
        }
    }
    fn verify(issued: &Issued, now: u64) {
        let registry = Registry::compile(
            1,
            &[Key {
                issuer_ref: "owned-hopae".into(),
                purpose: Purpose::Authentication,
                epoch: 1,
                public_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                    .verifying_key()
                    .to_bytes(),
            }],
            None,
        )
        .unwrap();
        registry
            .verify(&issued.context(), None, issued.bytes(), now)
            .unwrap();
        assert_eq!(issued.context().identity.kind, PrincipalKind::Service);
        assert_eq!(issued.context().identity.aal, 0);
        assert_eq!(issued.context().identity.revision, 1);
        assert_eq!(issued.context().identity.credential_generation, 1);
        assert_eq!(
            issued.context().identity_authority_epoch,
            "identity-1:service:1"
        );
    }
    #[tokio::test]
    async fn native_profile_proof_signs_aal_zero_and_refuses_scope_kind_and_revocation() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let mut owner = owner(&mut db, config(None));
        let snapshot = owner.snapshot();
        let mut authentication = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            authentication.verified_ms as i64,
        )));
        let issuer = issuer(clock.clone());
        let issued = issuer
            .issue_service(&authentication, request(), &|| Ok(()))
            .unwrap();
        verify(&issued, clock.now().0 as u64);
        assert_eq!(
            issued.context().identity.subject_ref,
            super::super::stable_subject(&authentication.evidence.subject)
        );
        let claims = receipt::verify(
            &issuer.signer.verifying_key(),
            issued.bytes(),
            Purpose::Authentication,
            &super::super::receipt_binding::digest(&issued.context(), None).unwrap(),
            clock.now().0 as u64,
        )
        .unwrap();
        assert_eq!(claims.claims().expires_ms, 350);
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Network,
            PrincipalKind::Workload,
        ] {
            authentication.evidence.subject.kind = kind;
            assert!(
                issuer
                    .issue_service(&authentication, request(), &|| panic!(
                        "wrong kind reached owner guard"
                    ))
                    .is_err()
            );
        }
        authentication.evidence.subject.kind = PrincipalKind::Service;
        assert!(
            issuer
                .issue_service(
                    &authentication,
                    Request {
                        service: "billing",
                        ..request()
                    },
                    &|| panic!("wrong service reached guard")
                )
                .is_err()
        );
        assert!(
            issuer
                .issue_service(
                    &authentication,
                    Request {
                        audience: "billing-api",
                        ..request()
                    },
                    &|| panic!("wrong audience reached guard")
                )
                .is_err()
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some("unknown-credential-at-least-thirty-two-bytes"),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some(TOKEN),
                    "198.51.100.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        owner
            .publish(
                &mut db,
                1,
                None,
                "operator",
                &|_| Some(TOKEN.into()),
                &|_| Ok(()),
            )
            .unwrap();
        let guard = || {
            if super::super::publication::read(&db)
                .map_err(|_| Refused)?
                .ok_or(Refused)?
                .revision
                == authentication.revision()
            {
                Ok(())
            } else {
                Err(Refused)
            }
        };
        assert!(
            issuer
                .issue_service(&authentication, request(), &guard)
                .is_err()
        );
        assert!(
            owner
                .snapshot()
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some(TOKEN),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn service_issuance_rechecks_final_guard_expiry_and_clock_rollback() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let owner = owner(&mut db, config(None));
        let authentication = owner
            .snapshot()
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            authentication.verified_ms as i64,
        )));
        let issuer = issuer(clock.clone());
        let calls = std::cell::Cell::new(0);
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| {
                    calls.set(calls.get() + 1);
                    if calls.get() == 2 {
                        Err(Refused)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| {
                    clock.set(Timestamp(350));
                    Ok(())
                })
                .is_err()
        );
        clock.set(Timestamp(100));
        assert!(
            issuer
                .issue_service(&authentication, request(), &|| panic!(
                    "expired service evidence revived"
                ))
                .is_err()
        );
    }
    #[tokio::test]
    async fn mixed_relay_and_native_proofs_preserve_distinct_namespace_and_aal_zero() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app=axum::Router::new().route("/verify",axum::routing::post(|headers:axum::http::HeaderMap|async move{
            let fake=headers[http::header::AUTHORIZATION].to_str().unwrap().contains("fake-mfa");
            let mut value=serde_json::json!({"active":true,"subject":"worker","service_id":"orders","expires_at":1000});
            if fake{value["aal"]=serde_json::json!(3);}
            axum::Json(value)
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let owner = owner(&mut db, config(Some(format!("http://{address}/verify"))));
        let snapshot = owner.snapshot();
        let native = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some(TOKEN),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let relay = snapshot
            .authenticate_for_receipt(
                "orders.example.test",
                443,
                Some("partner:owned-relay-credential"),
                "203.0.113.9".parse().unwrap(),
                100,
            )
            .await
            .unwrap();
        let clock = Arc::new(crate::crypto::TestClock::new(Timestamp(
            native.verified_ms.max(relay.verified_ms) as i64,
        )));
        let issuer = issuer(clock.clone());
        let native = issuer
            .issue_service(&native, request(), &|| Ok(()))
            .unwrap();
        let relay = issuer.issue_service(&relay, request(), &|| Ok(())).unwrap();
        verify(&native, clock.now().0 as u64);
        verify(&relay, clock.now().0 as u64);
        assert_ne!(
            native.context().identity.subject_ref,
            relay.context().identity.subject_ref
        );
        assert!(
            snapshot
                .authenticate_for_receipt(
                    "orders.example.test",
                    443,
                    Some("partner:fake-mfa-credential"),
                    "203.0.113.9".parse().unwrap(),
                    100
                )
                .await
                .is_err()
        );
        server.abort();
    }
}
