use super::*;
use crate::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, Policy, RetryCfg, Usb,
};
use crate::provider::{DatasetKeyDescriptor, KeyState, ZfsProvider};
use crate::service::LockchainService;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[derive(Clone)]
struct StubProvider;

impl ZfsProvider for StubProvider {
    type Error = LockchainError;

    fn encryption_root(&self, _dataset: &str) -> LockchainResult<String> {
        Ok("tank/secure".to_string())
    }

    fn locked_descendants(&self, _root: &str) -> LockchainResult<Vec<String>> {
        Ok(Vec::new())
    }

    fn load_key_tree(&self, _root: &str, _key: &[u8]) -> LockchainResult<Vec<String>> {
        Ok(Vec::new())
    }

    fn describe_datasets(&self, datasets: &[String]) -> LockchainResult<Vec<DatasetKeyDescriptor>> {
        Ok(datasets
            .iter()
            .map(|dataset| DatasetKeyDescriptor {
                dataset: dataset.clone(),
                encryption_root: dataset.clone(),
                state: KeyState::Available,
            })
            .collect())
    }
}

#[derive(Clone)]
struct MockProvider {
    root: String,
    locked: Arc<Mutex<HashSet<String>>>,
    observed_keys: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockProvider {
    fn new(root: &str, locked: &[&str]) -> Self {
        Self {
            root: root.to_string(),
            locked: Arc::new(Mutex::new(
                locked.iter().map(|ds| ds.to_string()).collect(),
            )),
            observed_keys: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ZfsProvider for MockProvider {
    type Error = LockchainError;

    fn encryption_root(&self, _dataset: &str) -> LockchainResult<String> {
        Ok(self.root.clone())
    }

    fn locked_descendants(&self, _root: &str) -> LockchainResult<Vec<String>> {
        let mut entries: Vec<String> = self.locked.lock().unwrap().iter().cloned().collect();
        entries.sort();
        Ok(entries)
    }

    fn load_key_tree(&self, _root: &str, key: &[u8]) -> LockchainResult<Vec<String>> {
        self.observed_keys.lock().unwrap().push(key.to_vec());
        let mut guard = self.locked.lock().unwrap();
        let mut unlocked: Vec<String> = guard.iter().cloned().collect();
        unlocked.sort();
        guard.clear();
        Ok(unlocked)
    }

    fn describe_datasets(&self, datasets: &[String]) -> LockchainResult<Vec<DatasetKeyDescriptor>> {
        let locked = self.locked.lock().unwrap();
        Ok(datasets
            .iter()
            .map(|ds| DatasetKeyDescriptor {
                dataset: ds.clone(),
                encryption_root: self.root.clone(),
                state: if locked.contains(ds) {
                    KeyState::Unavailable
                } else {
                    KeyState::Available
                },
            })
            .collect())
    }
}

#[test]
fn recover_key_writes_expected_material_and_permissions() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("recovered.key");
    let mut config = sample_config(dir.path());

    let salt = hex::encode([0x11u8; 16]);
    let xor = hex::encode([0x22u8; 32]);
    config.fallback.enabled = true;
    config.fallback.passphrase_salt = Some(salt);
    config.fallback.passphrase_xor = Some(xor);
    config.fallback.passphrase_iters = 1;

    let passphrase = b"correct horse battery staple";
    let dataset = "tank/secure";

    let provider = StubProvider;
    let expected_key = crate::fallback::derive_fallback_key(&config, passphrase).unwrap();

    let report = recover_key(
        &config,
        provider,
        dataset,
        RecoveryInput::Passphrase(passphrase),
        &output,
    )
    .unwrap();
    assert_eq!(report.title, format!("Recovered key material for {dataset}"));
    assert!(output.exists());

    let written = fs::read(&output).unwrap();
    assert_eq!(&written[..], &expected_key[..]);

    let metadata = fs::metadata(&output).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o400);

    let digest_line = report
        .events
        .iter()
        .find(|event| event.message.contains("SHA-256"))
        .map(|event| event.message.clone())
        .unwrap();
    assert!(
        digest_line.contains(&hex::encode(sha2::Sha256::digest(&written))),
        "digest event should mention written key"
    );
}

#[test]
fn recover_key_accepts_recovery_hex() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("hex-recovered.key");
    let config = sample_config(dir.path());
    let dataset = "tank/secure";
    let provider = StubProvider;
    let secret = "A5E2B91CF03D44B0A1C2F3E4D5C6B7A8FFEEDDCCBBAA99887766554433221100";

    let report = recover_key(
        &config,
        provider,
        dataset,
        RecoveryInput::Hex(secret),
        &output,
    )
    .unwrap();

    assert_eq!(report.title, format!("Recovered key material for {dataset}"));
    assert!(output.exists());
    let written = fs::read(&output).unwrap();
    let expected = hex::decode(secret).unwrap();
    assert_eq!(written, expected);

    let permissions = fs::metadata(&output).unwrap().permissions();
    assert_eq!(permissions.mode() & 0o777, 0o400);
    let security_event = report
        .events
        .iter()
        .find(|event| event.message.contains("recorded recovery key"))
        .cloned();
    assert!(
        security_event.is_some(),
        "expected security event referencing recorded recovery key"
    );
}

#[test]
fn drill_key_reports_unlock_progress() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("key.bin");
    fs::write(&key_path, [0xAAu8; 32]).unwrap();

    let mut config = sample_config(&key_path);
    config.usb.expected_sha256 = None;
    config.usb.device_label = Some("LOCKCHAINKEY".into());

    let provider = MockProvider::new("tank/secure", &["tank/secure"]);
    let report = drill_key(&config, provider.clone(), "tank/secure", true).unwrap();
    assert_eq!(report.title, "Drilled unlock sequence for tank/secure");

    let events: HashMap<_, _> = report
        .events
        .iter()
        .map(|event| (event.level, event.message.clone()))
        .collect();
    assert!(events
        .get(&WorkflowLevel::Success)
        .is_some_and(|msg| msg.contains("Unlocked tank/secure")));
    assert!(events
        .get(&WorkflowLevel::Info)
        .is_some_and(|msg| msg.contains("All descendants")));

    let observed = provider.observed_keys.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0], vec![0xAA; 32]);
}

fn sample_config(key_path: &Path) -> LockchainConfig {
    LockchainConfig {
        policy: Policy {
            datasets: vec!["tank/secure".to_string()],
            zfs_path: None,
            zpool_path: None,
            binary_path: None,
            allow_root: false,
        },
        crypto: CryptoCfg { timeout_secs: 5 },
        usb: Usb {
            key_hex_path: key_path.to_string_lossy().into_owned(),
            expected_sha256: None,
            device_label: Some("LOCKCHAINKEY".into()),
            ..Usb::default()
        },
        fallback: Fallback {
            enabled: false,
            askpass: false,
            askpass_path: None,
            passphrase_salt: None,
            passphrase_xor: None,
            passphrase_iters: 250_000,
        },
        retry: RetryCfg::default(),
        path: PathBuf::from("/tmp/lockchain-test-config.toml"),
        format: ConfigFormat::Toml,
    }
}

#[test]
fn usb_candidate_description_includes_metadata() {
    let candidate = UsbCandidate {
        disk: "/dev/sdb".into(),
        device: "/dev/sdb1".into(),
        label: Some("LOCKCHAINKEY".into()),
        model: Some("SanDisk Ultra".into()),
        serial: Some("123456".into()),
        size: Some("32G".into()),
        transport: Some("usb".into()),
        mountpoint: Some("/media/lockchain".into()),
    };
    let summary = candidate.describe();
    assert!(summary.contains("/dev/sdb1"));
    assert!(summary.contains("SanDisk Ultra"));
    assert!(summary.contains("disk /dev/sdb"));
    assert!(summary.contains("mounted /media/lockchain"));
}

#[test]
fn usb_prompt_formats_candidates() {
    let candidates = vec![
        UsbCandidate {
            disk: "/dev/sdb".into(),
            device: "/dev/sdb1".into(),
            label: Some("LOCKCHAINKEY".into()),
            model: Some("SanDisk".into()),
            serial: None,
            size: Some("32G".into()),
            transport: Some("usb".into()),
            mountpoint: None,
        },
        UsbCandidate {
            disk: "/dev/sdc".into(),
            device: "/dev/sdc".into(),
            label: None,
            model: Some("Kingston".into()),
            serial: Some("ABC123".into()),
            size: Some("64G".into()),
            transport: Some("usb".into()),
            mountpoint: Some("/media/tmp".into()),
        },
    ];

    let prompt = render_usb_selection_prompt(&candidates);
    assert!(prompt.contains("[1]"));
    assert!(prompt.contains("[2]"));
    assert!(prompt.contains("/dev/sdb1"));
    assert!(prompt.contains("Kingston"));
}
