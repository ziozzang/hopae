//! Native reference-only receiver resources. Preparing these grants no access.
use super::{permission_live::Client, receipt_keys::Refused};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub address: String,
    pub server_name: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub token_env: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub reference: String,
    pub token_env: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub authority: Authority,
    #[serde(default)]
    pub observed_clock_rates: Option<ObservedClockRates>,
    #[serde(default)]
    pub secrets: Vec<SecretReference>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedClockRates {
    pub source_ppm: u32,
    pub receiver_ppm: u32,
}
impl ObservedClockRates {
    fn compile(&self) -> Result<hopae_grpc::receipt_time::ClockRates, Refused> {
        hopae_grpc::receipt_time::ClockRates::new(self.source_ppm, self.receiver_ppm)
            .map_err(|_| Refused)
    }
}
/// No Clone/Debug/serde. Only native plan-owned references may resolve values.
pub struct Prepared {
    pub client: Arc<Client>,
    pub(crate) observed_rates: Option<hopae_grpc::receipt_time::ClockRates>,
    secrets: HashMap<String, Zeroizing<String>>,
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn env(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>, Refused> {
    let file = std::fs::File::open(path).map_err(|_| Refused)?;
    if !file.metadata().map_err(|_| Refused)?.is_file() {
        return Err(Refused);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(Refused);
    }
    Ok(bytes)
}
impl Configuration {
    pub fn validate(&self) -> Result<(), Refused> {
        self.observed_clock_rates
            .as_ref()
            .map(ObservedClockRates::compile)
            .transpose()?;
        let a = &self.authority;
        let uri: tonic::codegen::http::Uri = a.address.parse().map_err(|_| Refused)?;
        if a.address.len() > 256
            || uri.scheme_str() != Some("https")
            || uri.authority().is_none_or(|v| v.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|v| v.as_str() != "/")
            || uri.port_u16() == Some(0)
            || a.server_name.is_empty()
            || a.server_name.len() > 253
            || !a
                .server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || !a.ca.is_absolute()
            || !a.certificate.is_absolute()
            || !a.key.is_absolute()
            || !env(&a.token_env)
            || self.secrets.len() > 128
        {
            return Err(Refused);
        }
        let mut seen = HashSet::new();
        for secret in &self.secrets {
            if !id(&secret.reference) || !env(&secret.token_env) || !seen.insert(&secret.reference)
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
    pub fn validate_plans(&self, plans: &super::projection::Configuration) -> Result<(), Refused> {
        self.validate()?;
        super::projection::Projector::compile(plans.clone())?;
        for plan in &plans.plans {
            if let super::projection::Credential::BearerReference { secret_ref } = &plan.credential
                && !self
                    .secrets
                    .iter()
                    .any(|secret| secret.reference == *secret_ref)
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
    pub fn prepare(&self, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Prepared, Refused> {
        self.validate()?;
        let token = Zeroizing::new(resolve(&self.authority.token_env).ok_or(Refused)?);
        if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Refused);
        }
        let ca = read(&self.authority.ca)?;
        let certificate = read(&self.authority.certificate)?;
        let key = read(&self.authority.key)?;
        let client = Client::prepare(
            &self.authority.address,
            &self.authority.server_name,
            &ca,
            &certificate,
            &key,
            &token,
        )
        .map_err(|_| Refused)?;
        let mut secrets = HashMap::with_capacity(self.secrets.len());
        for reference in &self.secrets {
            let value = Zeroizing::new(resolve(&reference.token_env).ok_or(Refused)?);
            if !super::projection::valid_bearer(&value) {
                return Err(Refused);
            }
            secrets.insert(reference.reference.clone(), value);
        }
        Ok(Prepared {
            client: Arc::new(client),
            observed_rates: self
                .observed_clock_rates
                .as_ref()
                .map(ObservedClockRates::compile)
                .transpose()?,
            secrets,
        })
    }
}
impl Prepared {
    /// Native vault capability only. Call after verified paired admission, never
    /// as an ordinary authentication response or a request-selected secret API.
    pub fn resolve(&self, reference: &str) -> Result<Zeroizing<String>, Refused> {
        self.secrets
            .get(reference)
            .map(|value| Zeroizing::new(value.to_string()))
            .ok_or(Refused)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    fn config() -> serde_json::Value {
        let public = |seed| {
            STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
            )
        };
        serde_json::json!({
            "state_dir":"owned-state","portal":{"public_url":"https://auth.example.test"},
            "listen":{"grpc_gateway":"0.0.0.0:8785","native_gateway_tls":{"certificate":"/owned/server.pem","key":"/owned/server.key","client_ca":"/owned/ca.pem"}},
            "gateway":{"kind":"hangang","caller_key_env":"OWNED_CALLER"},
            "apps":[{"app_id":"orders","hosts":["app.example.test"]}],
            "authentication_gateway":{"authority_id":"owned","profiles":[{"service_id":"orders","host":"app.example.test","ports":[443],"realm":"services","api_keys":[{"token_env":"OWNED_API_KEY","subject":"worker"}],"networks":["192.0.2.0/24"]}]},
            "receipt_issuer":{"issuer_ref":"owned","key_epoch":1,"identity_authority_epoch":"epoch1","public_key":public(7),"seed_env":"OWNED_SIGNING_REFERENCE","scopes":[{"service":"orders","audience":"orders-api"}]},
            "receipt_permit_keys":[{"issuer_ref":"pumgye","key_epoch":1,"public_key":public(8)}],
            "credential_projection":{"revision":1,"plans":[{"service":"orders","audience":"orders-api","resource":"db:orders","action":"select","minimum_aal":0,"credential":{"type":"bearer_reference","secret_ref":"vault:orders"}}]},
            "projection_receiver":{"authority":{"address":"https://pumgye.example.test:443","server_name":"pumgye.example.test","ca":"/owned/ca.pem","certificate":"/owned/client.pem","key":"/owned/client.key","token_env":"OWNED_PROJECTION_BOOTSTRAP_MISSING_7AF"},"secrets":[{"reference":"vault:orders","token_env":"OWNED_ORIGIN"}]}
        })
    }
    #[test]
    fn observed_remote_rates_are_explicit_bounded_and_strict_optional() {
        let mut value = config()["projection_receiver"].clone();
        let strict: super::Configuration = serde_json::from_value(value.clone()).unwrap();
        assert!(strict.observed_clock_rates.is_none());
        assert!(strict.validate().is_ok());
        value["observed_clock_rates"] = serde_json::json!({"source_ppm":500,"receiver_ppm":500});
        let observed: super::Configuration = serde_json::from_value(value.clone()).unwrap();
        assert!(observed.validate().is_ok());
        value["observed_clock_rates"]["source_ppm"] = serde_json::json!(1_000_000);
        let invalid: super::Configuration = serde_json::from_value(value).unwrap();
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn actual_config_file_loader_accepts_only_explicit_valid_observed_rates() {
        let mut value = config();
        let file = tempfile::NamedTempFile::new().unwrap();
        let load = |value: &serde_json::Value| {
            std::fs::write(file.path(), value.to_string()).unwrap();
            crate::config::load(file.path())
        };
        assert!(
            load(&value)
                .unwrap()
                .projection_receiver
                .unwrap()
                .observed_clock_rates
                .is_none()
        );
        value["projection_receiver"]["observed_clock_rates"] =
            serde_json::json!({"source_ppm":500,"receiver_ppm":500});
        assert!(
            load(&value)
                .unwrap()
                .projection_receiver
                .unwrap()
                .observed_clock_rates
                .is_some()
        );
        value["projection_receiver"]["observed_clock_rates"]["source_ppm"] =
            serde_json::json!(1_000_000);
        assert!(load(&value).is_err());
        value["projection_receiver"]["observed_clock_rates"] =
            serde_json::json!({"source_ppm":500,"receiver_ppm":500,"fabricated":1});
        let error = load(&value).err().unwrap().to_string();
        assert!(error.contains("projection_receiver.observed_clock_rates.fabricated"));
    }
    #[test]
    fn receiver_configuration_requires_trusted_native_dependencies_and_reference_only_secrets() {
        let base = config();
        assert!(crate::config::parse(&base.to_string()).is_ok());
        for mutate in [
            |v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("receipt_issuer");
            },
            |v: &mut serde_json::Value| v["receipt_permit_keys"] = serde_json::json!([]),
            |v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("authentication_gateway");
            },
            |v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("credential_projection");
            },
            |v: &mut serde_json::Value| {
                v["listen"]
                    .as_object_mut()
                    .unwrap()
                    .remove("native_gateway_tls");
            },
            |v: &mut serde_json::Value| v["projection_receiver"]["secrets"] = serde_json::json!([]),
            |v: &mut serde_json::Value| {
                v["projection_receiver"]["authority"]["address"] =
                    serde_json::json!("http://pumgye.example.test")
            },
            |v: &mut serde_json::Value| {
                v["projection_receiver"]["secrets"][0]["token"] =
                    serde_json::json!("owned-inline-fixture-secret")
            },
        ] {
            let mut bad = base.clone();
            mutate(&mut bad);
            let error = crate::config::parse(&bad.to_string())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("owned-inline-fixture-secret"));
        }
        let parsed = crate::config::parse(&base.to_string()).unwrap();
        let mut resources = parsed.projection_receiver.unwrap();
        resources.authority.address = "https://pumgye.example.test/other".into();
        assert!(
            resources
                .prepare(&|_| panic!("invalid public resources cannot resolve secrets"))
                .is_err()
        );
    }
    #[tokio::test]
    async fn missing_receiver_resources_refuse_bind_before_creating_state() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("not-created");
        let mut value = config();
        value["state_dir"] = serde_json::json!(state);
        let parsed = crate::config::parse(&value.to_string()).unwrap();
        assert!(std::env::var("OWNED_PROJECTION_BOOTSTRAP_MISSING_7AF").is_err());
        let error = crate::app::bind(&parsed)
            .await
            .err()
            .expect("missing native resources must refuse");
        assert!(
            error
                .to_string()
                .contains("native projection resources unavailable")
        );
        assert!(!state.exists());
    }
    #[test]
    fn bearer_material_is_bounded_and_never_accepts_header_control_or_interior_padding() {
        for value in ["", "=", "bad\r\nvalue", "abc=def", "bearer with spaces"] {
            assert!(!super::super::projection::valid_bearer(value));
        }
        assert!(!super::super::projection::valid_bearer(&"x".repeat(4097)));
        assert!(super::super::projection::valid_bearer(
            "native-._~+/token=="
        ));
    }
}
