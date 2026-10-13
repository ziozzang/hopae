//! Native credential projection after authenticated chain admission. Not an HTTP
//! auth-response adapter: only the bound upstream request may receive this output.
use super::{projection_admission::Admission, receipt_keys::Refused};
use http::{HeaderName, HeaderValue};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub(crate) struct Scope {
    pub service: String,
    pub audience: String,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub aal: u8,
    pub request_sha256: [u8; 32],
    pub plan_revision: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub revision: u64,
    pub plans: Vec<Plan>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub service: String,
    pub audience: String,
    pub minimum_aal: u8,
    pub resource: String,
    pub action: String,
    pub credential: Credential,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    IdentityHeader,
    BearerReference { secret_ref: String },
}
pub struct Projector {
    revision: u64,
    plans: HashMap<String, HashMap<String, Plan>>,
}
/// No Clone, Debug or serde implementation: credential bytes must not enter
/// ordinary auth responses, telemetry or serialized management state.
pub struct Output {
    scope: Scope,
    name: HeaderName,
    value: Zeroizing<String>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
/// Administrator publication may select declared capabilities, not introduce a
/// secret reference, audience/resource/action or lower assurance requirement.
pub fn validate_capabilities(
    desired: &Configuration,
    declared: Option<&Configuration>,
) -> Result<(), Refused> {
    Projector::compile(desired.clone())?;
    let declared = declared.ok_or(Refused)?;
    for plan in &desired.plans {
        let original = declared
            .plans
            .iter()
            .find(|p| p.service == plan.service && p.audience == plan.audience)
            .ok_or(Refused)?;
        let same_credential = match (&plan.credential, &original.credential) {
            (Credential::IdentityHeader, Credential::IdentityHeader) => true,
            (
                Credential::BearerReference { secret_ref: a },
                Credential::BearerReference { secret_ref: b },
            ) => a == b,
            _ => false,
        };
        if plan.resource != original.resource
            || plan.action != original.action
            || plan.minimum_aal < original.minimum_aal
            || !same_credential
        {
            return Err(Refused);
        }
    }
    Ok(())
}
impl Projector {
    /// Compile reference-only native plans. Secret resolution is deferred until
    /// authenticated receipt admission and the transaction's first live guard.
    pub fn compile(config: Configuration) -> Result<Self, Refused> {
        if !(1..=9_007_199_254_740_991).contains(&config.revision)
            || config.plans.is_empty()
            || config.plans.len() > 128
        {
            return Err(Refused);
        }
        let mut plans: HashMap<String, HashMap<String, Plan>> = HashMap::new();
        for plan in config.plans {
            if !identifier(&plan.service)
                || !identifier(&plan.audience)
                || !identifier(&plan.resource)
                || !identifier(&plan.action)
                || plan.minimum_aal > 3
            {
                return Err(Refused);
            }
            if let Credential::BearerReference { secret_ref } = &plan.credential
                && !identifier(secret_ref)
            {
                return Err(Refused);
            }
            if plans
                .entry(plan.service.clone())
                .or_default()
                .insert(plan.audience.clone(), plan)
                .is_some()
            {
                return Err(Refused);
            }
        }
        Ok(Self {
            revision: config.revision,
            plans,
        })
    }
    /// `resolve` is a native vault capability, never a script callback. Guard must
    /// recheck current plan revision and all live owner state before and after work.
    /// Output is returned only after both nonces and owner work successfully commit.
    pub fn project(
        &self,
        admission: Admission,
        db: &mut Connection,
        clock: &dyn Fn() -> u64,
        guard: &dyn Fn(&Connection) -> Result<(), Refused>,
        resolve: &dyn Fn(&str) -> Result<Zeroizing<String>, Refused>,
    ) -> Result<Output, Refused> {
        let scope = &admission.scope;
        let plan = self
            .plans
            .get(scope.service.as_str())
            .and_then(|p| p.get(scope.audience.as_str()))
            .ok_or(Refused)?;
        if self.revision != scope.plan_revision
            || scope.aal < plan.minimum_aal
            || scope.resource != plan.resource
            || scope.action != plan.action
        {
            return Err(Refused);
        }
        let scope = Scope {
            service: scope.service.clone(),
            audience: scope.audience.clone(),
            subject: scope.subject.clone(),
            resource: scope.resource.clone(),
            action: scope.action.clone(),
            aal: scope.aal,
            request_sha256: scope.request_sha256,
            plan_revision: scope.plan_revision,
            issued_ms: scope.issued_ms,
            expires_ms: scope.expires_ms,
        };
        admission.consume(db, clock, guard, |_| {
            let (name, value) = match &plan.credential {
                Credential::IdentityHeader => (
                    HeaderName::from_static("x-hopae-subject"),
                    Zeroizing::new(scope.subject.clone()),
                ),
                Credential::BearerReference { secret_ref } => {
                    let secret = resolve(secret_ref)?;
                    // RFC 6750 b64token with trailing padding only. No whitespace,
                    // control characters, arbitrary header names or concatenation.
                    if secret.len() > 4096 {
                        return Err(Refused);
                    }
                    let token = secret.trim_end_matches('=');
                    if token.is_empty()
                        || !token
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
                    {
                        return Err(Refused);
                    }
                    (
                        HeaderName::from_static("authorization"),
                        Zeroizing::new(format!("Bearer {}", secret.as_str())),
                    )
                }
            };
            Ok(Output { scope, name, value })
        })
    }
}
impl Output {
    /// Final native upstream binding check. Hangang must remove client/protected
    /// headers and install this value only after permission, without redirects or
    /// route rematching. `now` must obey the trusted clock/rollback fence.
    pub fn into_header(
        self,
        service: &str,
        audience: &str,
        request_sha256: &[u8; 32],
        now: u64,
    ) -> Result<(HeaderName, HeaderValue), Refused> {
        if service != self.scope.service
            || audience != self.scope.audience
            || *request_sha256 != self.scope.request_sha256
            || now < self.scope.issued_ms
            || now >= self.scope.expires_ms
        {
            return Err(Refused);
        }
        let mut value = HeaderValue::from_str(self.value.as_str()).map_err(|_| Refused)?;
        value.set_sensitive(true);
        Ok((self.name, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plans_are_bounded_reference_only_and_reject_duplicate_scopes() {
        let plan = Plan {
            service: "orders".into(),
            audience: "orders-api".into(),
            resource: "orders".into(),
            action: "read".into(),
            minimum_aal: 2,
            credential: Credential::BearerReference {
                secret_ref: "vault:owned-token".into(),
            },
        };
        assert!(
            Projector::compile(Configuration {
                revision: 1,
                plans: vec![plan.clone()]
            })
            .is_ok()
        );
        for config in [
            Configuration {
                revision: 0,
                plans: vec![plan.clone()],
            },
            Configuration {
                revision: 9_007_199_254_740_992,
                plans: vec![plan.clone()],
            },
            Configuration {
                revision: 1,
                plans: vec![],
            },
            Configuration {
                revision: 1,
                plans: vec![plan.clone(), plan.clone()],
            },
            Configuration {
                revision: 1,
                plans: vec![plan.clone(); 129],
            },
        ] {
            assert!(Projector::compile(config).is_err());
        }
        for field in 0..6 {
            let mut bad = plan.clone();
            match field {
                0 => bad.service.clear(),
                1 => bad.audience = "bad\r\nheader".into(),
                2 => bad.resource = "a".repeat(129),
                3 => bad.action = "read write".into(),
                4 => bad.minimum_aal = 4,
                _ => {
                    bad.credential = Credential::BearerReference {
                        secret_ref: "https://caller.example/key".into(),
                    }
                }
            }
            assert!(
                Projector::compile(Configuration {
                    revision: 1,
                    plans: vec![bad]
                })
                .is_err()
            );
        }
        let mut json = serde_json::to_value(Configuration {
            revision: 1,
            plans: vec![plan],
        })
        .unwrap();
        json["plans"][0]["credential"]["value"] = serde_json::json!("caller-supplied-token");
        assert!(serde_json::from_value::<Configuration>(json).is_err());
    }
}
