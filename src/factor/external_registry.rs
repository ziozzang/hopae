//! Immutable, fully compiled external-MFA snapshot. Build before owner state or
//! listeners are touched; publication and browser selection remain native duties.
use super::external_transport::{Config, Connector};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, sync::Arc};

pub struct Registry {
    connectors: BTreeMap<String, Arc<Connector>>,
}
impl Registry {
    pub fn compile(
        configs: &[Config],
        env: &dyn Fn(&str) -> Option<String>,
        previous: Option<&Self>,
    ) -> Result<Self> {
        ensure!(configs.len() <= 64, "external factor capacity exceeded");
        let mut connectors = BTreeMap::new();
        // Validate every identity before resolving secrets or constructing clients.
        for config in configs {
            config.validate()?;
            ensure!(
                !connectors.contains_key(&config.factor),
                "duplicate external factor id"
            );
            connectors.insert(config.factor.clone(), ());
        }
        let mut compiled = BTreeMap::new();
        for config in configs {
            let candidate = Connector::compile(config, env)?;
            let connector = previous
                .and_then(|old| old.get(&config.factor))
                .filter(|old| old.same_binding(&candidate))
                .cloned()
                .unwrap_or_else(|| Arc::new(candidate));
            compiled.insert(config.factor.clone(), connector);
        }
        Ok(Self {
            connectors: compiled,
        })
    }
    /// Publish the complete operator-approved set atomically, including removals.
    /// Activate this registry only after success; CAS refusal retains the old view.
    pub async fn publish_authorized_configuration(
        &self,
        store: &dyn crate::store::Factors,
        config_generation: u64,
        expected_revision: u64,
    ) -> crate::store::StoreResult<u64> {
        store
            .publish_external_snapshot(crate::store::ExternalFactorSnapshot {
                authorities: self
                    .connectors
                    .values()
                    .map(|connector| connector.authority())
                    .collect(),
                config_generation,
                expected_revision,
            })
            .await
    }
    pub fn get(&self, factor: &str) -> Option<&Arc<Connector>> {
        self.connectors.get(factor)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<Connector>)> {
        self.connectors
            .iter()
            .map(|(id, connector)| (id.as_str(), connector))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config(id: &str) -> Config {
        Config {
            factor: id.into(),
            configuration_revision: 1,
            url: "https://verifier.example.test/check".into(),
            verifier_key_env: "OWNED_FACTOR_KEY".into(),
            timeout_ms: 100,
            allow_private_endpoints: false,
            ca: None,
        }
    }
    #[test]
    fn duplicate_ids_fail_before_secret_resolution_and_missing_secrets_refuse_snapshot() {
        let configs = [config("push"), config("push")];
        assert!(Registry::compile(&configs, &|_| panic!("must validate first"), None).is_err());
        assert!(Registry::compile(&[config("push")], &|_| None, None).is_err());
        assert!(
            Registry::compile(
                &vec![config("push"); 65],
                &|_| panic!("capacity first"),
                None
            )
            .is_err()
        );
    }
    #[test]
    fn unchanged_connectors_preserve_pool_and_circuit_while_material_changes_replace_them() {
        let configs = [config("push")];
        let original = Registry::compile(&configs, &|_| Some("a".repeat(32)), None).unwrap();
        let same = Registry::compile(&configs, &|_| Some("a".repeat(32)), Some(&original)).unwrap();
        assert!(Arc::ptr_eq(
            original.get("push").unwrap(),
            same.get("push").unwrap()
        ));
        let rotated =
            Registry::compile(&configs, &|_| Some("b".repeat(32)), Some(&original)).unwrap();
        assert!(!Arc::ptr_eq(
            original.get("push").unwrap(),
            rotated.get("push").unwrap()
        ));
        let removed = Registry::compile(&[], &|_| None, Some(&original)).unwrap();
        assert!(removed.get("push").is_none());
        assert_eq!(original.iter().count(), 1);
    }
}
