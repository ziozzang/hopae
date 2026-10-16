//! Relying-party tests with `webauthn-authenticator-rs` software authenticators.

use super::*;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::softtoken::SoftToken;

const PORTAL: &str = "https://auth.example.test";

fn rp() -> RelyingParty {
    RelyingParty::compile(&Configuration::default(), PORTAL).unwrap()
}

fn origin(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    // `true`: the software key reports user verification (it has no biometrics).
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn register(rp: &RelyingParty, a: &mut WebauthnAuthenticator<SoftPasskey>) -> Registered {
    let (options, state) = rp
        .start_registration([9; 16], "alice@example.test", "Alice", vec![], false)
        .unwrap();
    let response = a.do_registration(origin(PORTAL), options).unwrap();
    rp.finish_registration(&serde_json::to_string(&response).unwrap(), &state)
        .unwrap()
}

fn assert_with(
    rp: &RelyingParty,
    a: &mut WebauthnAuthenticator<SoftPasskey>,
    stored: &Registered,
    at: &str,
) -> Result<Asserted, Failure> {
    let creds = [StoredCredential {
        credential: &stored.credential,
        assurance: stored.assurance,
    }];
    let (options, state) = rp.start_authentication(&creds).unwrap();
    let response = a
        .do_authentication(origin(at), options)
        .map_err(|_| Failure::Rejected)?;
    rp.finish_authentication(&serde_json::to_string(&response).unwrap(), &state, &creds)
}

#[test]
fn rp_id_defaults_to_the_portal_host_and_only_parents_are_allowed() {
    assert_eq!(effective_rp_id(None, PORTAL).unwrap(), "auth.example.test");
    assert_eq!(
        effective_rp_id(Some("example.test"), PORTAL).unwrap(),
        "example.test"
    );
    assert_eq!(
        effective_rp_id(Some("Auth.Example.Test."), PORTAL).unwrap(),
        "auth.example.test"
    );
    for bad in [
        "test",
        "other.example.test",
        "uth.example.test",
        "127.0.0.1",
        "",
        "evil.test",
    ] {
        assert!(effective_rp_id(Some(bad), PORTAL).is_err(), "{bad}");
    }
    assert!(effective_rp_id(None, "https://127.0.0.1:8443").is_err());
    let cfg = Configuration {
        rp_id: None,
        rp_name: Some(String::new()),
        passwordless: false,
        high_assurance: Some(HighAssuranceConfiguration {
            attestation_ca_files: vec![],
            aaguids: vec!["00000000-0000-0000-0000-000000000000".into()],
        }),
    };
    assert_eq!(cfg.validate(PORTAL).len(), 3);
}

#[test]
fn register_and_authenticate_with_a_user_verified_passkey() {
    let rp = rp();
    let mut a = authenticator();
    let reg = register(&rp, &mut a);
    assert!(reg.user_verified);
    assert_eq!(reg.assurance, Assurance::Aal2);
    assert!(!reg.attested);
    assert!(
        reg.aaguid.is_none(),
        "the software key reports a zero AAGUID"
    );
    assert!(reg.credential_id.len() >= 16);
    let first = assert_with(&rp, &mut a, &reg, PORTAL).unwrap();
    assert_eq!(first.credential_id, reg.credential_id);
    assert_eq!(first.assurance, Assurance::Aal2);
    assert!(first.sign_count >= 1);
    // The updated credential carries the new counter.
    let next = Registered {
        credential: first.credential.clone(),
        ..reg.clone()
    };
    let second = assert_with(&rp, &mut a, &next, PORTAL).unwrap();
    assert!(second.sign_count > first.sign_count);
}

#[test]
fn a_counter_that_does_not_advance_is_a_clone_signal() {
    let rp = rp();
    let mut a = authenticator();
    let reg = register(&rp, &mut a);
    let used = assert_with(&rp, &mut a, &reg, PORTAL).unwrap();
    // The server already saw a much higher counter: this assertion regresses.
    let mut cred: Credential = serde_json::from_str(&used.credential).unwrap();
    cred.counter = 1000;
    let stale = Registered {
        credential: serde_json::to_string(&cred).unwrap(),
        ..reg
    };
    assert_eq!(
        assert_with(&rp, &mut a, &stale, PORTAL).unwrap_err(),
        Failure::CounterRegression
    );
}

#[test]
fn an_assertion_from_another_origin_is_refused() {
    // The RP ID is the parent domain, so a browser on a sibling host may
    // legitimately ask; Hopae still pins the exact portal origin.
    let cfg = Configuration {
        rp_id: Some("example.test".into()),
        ..Configuration::default()
    };
    let rp = RelyingParty::compile(&cfg, PORTAL).unwrap();
    let mut a = authenticator();
    let reg = register(&rp, &mut a);
    assert_eq!(
        assert_with(&rp, &mut a, &reg, "https://app.example.test").unwrap_err(),
        Failure::Rejected
    );
    assert_eq!(
        assert_with(&rp, &mut a, &reg, "https://auth.example.test:8443").unwrap_err(),
        Failure::Rejected
    );
    assert!(assert_with(&rp, &mut a, &reg, PORTAL).is_ok());
}

#[test]
fn an_assertion_for_another_rp_id_is_refused() {
    let rp = rp();
    let mut a = authenticator();
    let reg = register(&rp, &mut a);
    let creds = [StoredCredential {
        credential: &reg.credential,
        assurance: reg.assurance,
    }];
    let (mut options, state) = rp.start_authentication(&creds).unwrap();
    // A phishing relay presents the same challenge under its own RP ID.
    options.public_key.rp_id = "example.test".into();
    let response = a.do_authentication(origin(PORTAL), options).unwrap();
    assert_eq!(
        rp.finish_authentication(&serde_json::to_string(&response).unwrap(), &state, &creds)
            .unwrap_err(),
        Failure::Rejected
    );
}

#[test]
fn an_assertion_for_another_challenge_is_refused() {
    let rp = rp();
    let mut a = authenticator();
    let reg = register(&rp, &mut a);
    let creds = [StoredCredential {
        credential: &reg.credential,
        assurance: reg.assurance,
    }];
    let (options, _state_a) = rp.start_authentication(&creds).unwrap();
    let (_, state_b) = rp.start_authentication(&creds).unwrap();
    let response = a.do_authentication(origin(PORTAL), options).unwrap();
    assert_eq!(
        rp.finish_authentication(&serde_json::to_string(&response).unwrap(), &state_b, &creds)
            .unwrap_err(),
        Failure::Rejected
    );
}

#[test]
fn registration_without_user_verification_is_refused() {
    let rp = rp();
    let mut a = authenticator();
    let (options, state) = rp
        .start_registration([9; 16], "a", "A", vec![], false)
        .unwrap();
    let mut json = serde_json::to_value(&options).unwrap();
    json["publicKey"]["authenticatorSelection"]["userVerification"] = "discouraged".into();
    let options: CreationChallengeResponse = serde_json::from_value(json).unwrap();
    let response = a.do_registration(origin(PORTAL), options).unwrap();
    assert_eq!(
        rp.finish_registration(&serde_json::to_string(&response).unwrap(), &state)
            .unwrap_err(),
        Failure::Rejected
    );
}

#[test]
fn malformed_input_is_refused_without_panicking() {
    let rp = rp();
    assert_eq!(
        rp.finish_registration("{}", "{}").unwrap_err(),
        Failure::Malformed
    );
    assert_eq!(
        rp.finish_authentication("not json", "{}", &[]).unwrap_err(),
        Failure::Malformed
    );
    assert!(RelyingParty::response_credential_id("{}").is_none());
    assert!(rp.start_authentication(&[]).is_err());
}

#[test]
fn high_assurance_registration_needs_an_attested_allowlisted_key() {
    let (token, ca) = SoftToken::new(true).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("ca.pem");
    std::fs::write(&pem, ca.to_pem().unwrap()).unwrap();
    let allowed = webauthn_authenticator_rs::softtoken::AAGUID.to_string();
    let cfg = |aaguid: &str| Configuration {
        rp_id: None,
        rp_name: None,
        passwordless: false,
        high_assurance: Some(HighAssuranceConfiguration {
            attestation_ca_files: vec![pem.clone()],
            aaguids: vec![aaguid.into()],
        }),
    };
    let rp = RelyingParty::compile(&cfg(&allowed), PORTAL).unwrap();
    assert!(rp.high_assurance());
    let mut a = WebauthnAuthenticator::new(token);
    let (options, state) = rp
        .start_registration([3; 16], "a", "A", vec![], true)
        .unwrap();
    let response = a.do_registration(origin(PORTAL), options).unwrap();
    let reg = rp
        .finish_registration(&serde_json::to_string(&response).unwrap(), &state)
        .unwrap();
    assert!(reg.attested);
    assert_eq!(reg.assurance, Assurance::Aal3);
    assert_eq!(
        reg.aaguid,
        Some(*webauthn_authenticator_rs::softtoken::AAGUID.as_bytes())
    );
    // The same key under an allowlist that does not name its AAGUID.
    let other =
        RelyingParty::compile(&cfg("cb69481e-8ff7-4039-93ec-0a2729a154a8"), PORTAL).unwrap();
    let (token, _) = SoftToken::new(true).unwrap();
    let mut b = WebauthnAuthenticator::new(token);
    let (options, state) = other
        .start_registration([4; 16], "a", "A", vec![], true)
        .unwrap();
    let response = b.do_registration(origin(PORTAL), options).unwrap();
    assert_eq!(
        other
            .finish_registration(&serde_json::to_string(&response).unwrap(), &state)
            .unwrap_err(),
        Failure::NotAllowed
    );
    // Without high assurance configured the ceremony does not exist.
    assert_eq!(rp_plain_high().unwrap_err(), Failure::NotAllowed);
}

fn rp_plain_high() -> Result<(), Failure> {
    rp().start_registration([1; 16], "a", "A", vec![], true)
        .map(|_| ())
}

#[test]
fn excluded_credentials_are_listed_in_the_options() {
    let rp = rp();
    let (options, _) = rp
        .start_registration([1; 16], "a", "A", vec![vec![5; 32]], false)
        .unwrap();
    let json = serde_json::to_value(&options).unwrap();
    assert_eq!(
        json["publicKey"]["excludeCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(json["publicKey"]["rp"]["id"], "auth.example.test");
}

#[test]
fn known_aaguids_have_names_and_parsing_is_defensive() {
    let gpm = *Uuid::parse_str("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
        .unwrap()
        .as_bytes();
    assert_eq!(authenticator_name(&gpm), Some("Google Password Manager"));
    assert_eq!(authenticator_name(&[0; 16]), None);
    for (id, _) in KNOWN_AUTHENTICATORS {
        assert!(Uuid::parse_str(id).is_ok(), "{id}");
    }
    assert!(aaguid_of(b"").is_none());
    assert!(aaguid_of(&[0xa0]).is_none());
}

#[test]
fn browser_json_with_extra_fields_is_accepted() {
    // `PublicKeyCredential.toJSON()` adds fields the library does not model.
    let rp = rp();
    let mut a = authenticator();
    let (options, state) = rp
        .start_registration([9; 16], "a", "A", vec![], false)
        .unwrap();
    let response = a.do_registration(origin(PORTAL), options).unwrap();
    let mut json = serde_json::to_value(&response).unwrap();
    json["authenticatorAttachment"] = "platform".into();
    let ext = json.as_object_mut().unwrap().remove("extensions").unwrap();
    json["clientExtensionResults"] = ext;
    json["response"]["publicKeyAlgorithm"] = (-7).into();
    json["response"]["transports"] = serde_json::json!(["internal", "hybrid", "smart-card"]);
    let reg = rp.finish_registration(&json.to_string(), &state).unwrap();
    assert_eq!(
        reg.transports,
        vec!["internal".to_string(), "hybrid".to_string()]
    );
}
