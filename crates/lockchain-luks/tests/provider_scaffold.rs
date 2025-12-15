use lockchain_core::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, LuksCfg, Policy, ProviderCfg, RetryCfg,
    Usb, ZfsCfg,
};
use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_core::provider::LuksKeyProvider;
use lockchain_core::service::{LockchainService, UnlockOptions};
use lockchain_luks::SystemLuksProvider;
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[test]
fn system_provider_status_returns_not_implemented() {
    let config = sample_luks_config("vault");
    let provider = SystemLuksProvider::from_config(&config).expect("provider should construct");

    let err = provider.status("vault").expect_err("expected not implemented error");
    match err {
        LockchainError::Provider(message) => assert_eq!(message, "not implemented"),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn mock_provider_harness_unlocks_mapping_via_service() -> LockchainResult<()> {
    let config = Arc::new(sample_luks_config("vault"));
    let mock = MockLuksProvider::new([("vault", LuksState::Inactive)]);
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(mock));

    let before = service.status("vault")?;
    assert!(before.root_locked);

    let report = service.unlock(
        "vault",
        UnlockOptions {
            key_override: Some(vec![0xAA; 32]),
            ..UnlockOptions::default()
        },
    )?;
    assert!(!report.already_unlocked);

    let after = service.status("vault")?;
    assert!(!after.root_locked);
    Ok(())
}

#[derive(Clone)]
struct MockLuksProvider {
    state: Arc<Mutex<HashMap<String, LuksState>>>,
}

impl MockLuksProvider {
    fn new<const N: usize>(entries: [(&str, LuksState); N]) -> Self {
        let mut state = HashMap::new();
        for (name, mapping_state) in entries {
            state.insert(name.to_string(), mapping_state);
        }
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }
}

impl LuksProvider for MockLuksProvider {
    type Error = LockchainError;

    fn list_mappings(&self) -> LockchainResult<Vec<LuksMappingDescriptor>> {
        let state = self.state.lock().unwrap();
        let mut mappings: Vec<LuksMappingDescriptor> = state
            .iter()
            .map(|(name, mapping_state)| LuksMappingDescriptor {
                name: name.clone(),
                source: "UUID=MOCK".to_string(),
                state: mapping_state.clone(),
            })
            .collect();
        mappings.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(mappings)
    }

    fn unlock_mapping(&self, name: &str, _key: &[u8]) -> LockchainResult<()> {
        let mut state = self.state.lock().unwrap();
        let entry = state.get_mut(name).ok_or_else(|| {
            LockchainError::InvalidConfig(format!("mock mapping not declared: {name}"))
        })?;
        *entry = LuksState::Active;
        Ok(())
    }

    fn mapping_state(&self, name: &str) -> LockchainResult<LuksState> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_else(|| LuksState::Unknown("mock mapping not declared".into())))
    }
}

fn sample_luks_config(target: &str) -> LockchainConfig {
    LockchainConfig {
        provider: ProviderCfg::default(),
        policy: Policy {
            targets: vec![target.to_string()],
            binary_path: None,
            allow_root: false,
            legacy_zfs_path: None,
            legacy_zpool_path: None,
        },
        zfs: ZfsCfg::default(),
        crypto: CryptoCfg { timeout_secs: 5 },
        luks: LuksCfg::default(),
        usb: Usb::default(),
        fallback: Fallback::default(),
        retry: RetryCfg::default(),
        path: PathBuf::from("/etc/lockchain.toml"),
        format: ConfigFormat::Toml,
    }
}

