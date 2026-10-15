//! Owned in-process OIDC issuer: real JWT signature, nonce and PKCE exchanges.
use crate::crypto::{Clock, TestClock};
use axum::{
    Json, Router,
    extract::{Form, Query, State},
    response::Redirect,
    routing::{get, post},
};
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};
struct Entropy;
impl rsa::rand_core::RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, b: &mut [u8]) {
        crate::crypto::Rng::fill(&crate::crypto::OsRng, b)
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(b);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for Entropy {}
struct Key {
    encoding: jsonwebtoken::EncodingKey,
    n: String,
    e: String,
}
fn key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let k = rsa::RsaPrivateKey::new(&mut Entropy, 2048).unwrap();
        Key {
            encoding: jsonwebtoken::EncodingKey::from_rsa_der(k.to_pkcs1_der().unwrap().as_bytes()),
            n: data_encoding::BASE64URL_NOPAD.encode(&k.n().to_bytes_be()),
            e: data_encoding::BASE64URL_NOPAD.encode(&k.e().to_bytes_be()),
        }
    })
}
struct StateData {
    issuer: OnceLock<String>,
    clock: Arc<TestClock>,
    codes: Mutex<HashMap<String, HashMap<String, String>>>,
    next: std::sync::atomic::AtomicU64,
    on_token: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
pub(super) struct Issuer {
    pub(super) url: String,
    _server: super::server::Served,
    state: Arc<StateData>,
}
impl Issuer {
    pub(super) fn on_token(&self, callback: impl FnOnce() + Send + 'static) {
        *self.state.on_token.lock().unwrap() = Some(Box::new(callback));
    }
    pub(super) fn new(clock: Arc<TestClock>) -> Self {
        let _ = key();
        let state = Arc::new(StateData {
            issuer: OnceLock::new(),
            clock,
            codes: Mutex::new(HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
            on_token: Mutex::new(None),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        let server = super::server::Served::start(router);
        let url = format!("http://{}", server.addr);
        state.issuer.set(url.clone()).unwrap();
        Self {
            url,
            _server: server,
            state,
        }
    }
}
async fn discovery(State(s): State<Arc<StateData>>) -> Json<Value> {
    let u = s.issuer.get().unwrap();
    Json(
        json!({"issuer":u,"authorization_endpoint":format!("{u}/authorize"),"token_endpoint":format!("{u}/token"),"jwks_uri":format!("{u}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}),
    )
}
async fn jwks() -> Json<Value> {
    Json(
        json!({"keys":[{"kty":"RSA","kid":"native-owned","use":"sig","alg":"RS256","n":key().n,"e":key().e}]}),
    )
}
async fn authorize(
    State(s): State<Arc<StateData>>,
    Query(q): Query<HashMap<String, String>>,
) -> Redirect {
    assert_eq!(
        q.get("client_id").map(String::as_str),
        Some("native-owned-client")
    );
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let code = format!(
        "owned-code-{}",
        s.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut target = url::Url::parse(q.get("redirect_uri").unwrap()).unwrap();
    target
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", q.get("state").unwrap());
    s.codes.lock().unwrap().insert(code, q);
    Redirect::temporary(target.as_str())
}
async fn token(
    State(s): State<Arc<StateData>>,
    Form(q): Form<HashMap<String, String>>,
) -> Json<Value> {
    let original = s
        .codes
        .lock()
        .unwrap()
        .remove(q.get("code").unwrap())
        .expect("single-use native authorization code");
    assert_eq!(q.get("redirect_uri"), original.get("redirect_uri"));
    let verifier = q.get("code_verifier").expect("PKCE verifier");
    assert_eq!(
        original.get("code_challenge").unwrap(),
        &data_encoding::BASE64URL_NOPAD.encode(&crate::crypto::sha256(verifier.as_bytes()).0)
    );
    let callback = s.on_token.lock().unwrap().take();
    if let Some(callback) = callback {
        callback();
    }
    let now = s.clock.now().secs();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("native-owned".into());
    let token=jsonwebtoken::encode(&header,&json!({"iss":s.issuer.get().unwrap(),"sub":"owned-native-subject","aud":"native-owned-client","iat":now,"exp":now+300,"auth_time":now,"nonce":original.get("nonce").unwrap(),"name":"Native"}),&key().encoding).unwrap();
    Json(
        json!({"id_token":token,"access_token":"owned-nonproduction-access","token_type":"Bearer","expires_in":300}),
    )
}
