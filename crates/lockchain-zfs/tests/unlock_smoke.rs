use lockchain_core::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, LuksCfg, Policy, ProviderCfg, RetryCfg,
    Usb, ZfsCfg,
};
use lockchain_core::service::{LockchainService, UnlockOptions};
use lockchain_core::LockchainResult;
use lockchain_zfs::SystemZfsProvider;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

const DEFAULT_STATE: &str = r#"{"tank/secure":"unavailable","tank/secure/home":"unavailable"}"#;

const FAKE_ZFS_SCRIPT: &str = r#"#!/usr/bin/env python3
import json
import os
import sys

STATE = os.environ.get("FAKE_ZFS_STATE")
if not STATE:
    print("FAKE_ZFS_STATE not set", file=sys.stderr)
    sys.exit(3)

try:
    with open(STATE, "r", encoding="utf-8") as fh:
        state = json.load(fh)
except FileNotFoundError:
    state = {}
except json.JSONDecodeError:
    state = {}

def save():
    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump(state, fh)

def ensure_dataset_known(dataset):
    if dataset not in ("tank/secure", "tank/secure/home"):
        print(f"cannot open '{dataset}': dataset does not exist", file=sys.stderr)
        sys.exit(1)

args = sys.argv[1:]
if not args:
    sys.exit(2)

if args[0] == "list" and len(args) >= 6 and args[1] == "-H" and args[2] == "-r" and args[3] == "-o" and args[4] == "name,encryptionroot":
    root = args[5]
    ensure_dataset_known(root)
    print("tank/secure\ttank/secure")
    print("tank/secure/home\ttank/secure")
    sys.exit(0)

if args[0] == "get" and len(args) >= 7 and args[1] == "-H" and args[2] == "-r" and args[3] == "-o" and args[4] == "name,value" and args[5] == "keystatus":
    root = args[6]
    ensure_dataset_known(root)
    for name in ("tank/secure", "tank/secure/home"):
        value = state.get(name, "unavailable")
        print(f"{name}\t{value}")
    sys.exit(0)

if args[0] == "get" and len(args) >= 6 and args[1] == "-H" and args[2] == "-o" and args[3] == "value" and args[4] == "keystatus":
    dataset = args[5]
    ensure_dataset_known(dataset)
    print(state.get(dataset, "unavailable"))
    sys.exit(0)

if args[0] == "get" and len(args) >= 6 and args[1] == "-H" and args[2] == "-o" and args[3] == "value" and args[4] == "encryptionroot":
    dataset = args[5]
    ensure_dataset_known(dataset)
    print("tank/secure")
    sys.exit(0)

if args[0] == "load-key" and len(args) >= 4:
    dataset = args[3]
    ensure_dataset_known(dataset)
    state[dataset] = "available"
    save()
    sys.exit(0)

print("unexpected args: " + " ".join(args), file=sys.stderr)
sys.exit(2)
"#;

const FAKE_ZPOOL_SCRIPT: &str = r#"#!/usr/bin/env python3
import os
import sys

args = sys.argv[1:]
if len(args) >= 5 and args[0] == "list" and args[1] == "-H" and args[2] == "-o" and args[3] == "name,health":
    pool = args[4]
    if pool != "tank":
        print(f"cannot open '{pool}': no such pool", file=sys.stderr)
        sys.exit(1)
    health = os.environ.get("FAKE_ZPOOL_HEALTH", "ONLINE")
    print(f"{pool}\t{health}")
    sys.exit(0)

print("unexpected args: " + " ".join(args), file=sys.stderr)
sys.exit(2)
"#;

#[test]
fn unlock_smoke_unlocks_dev_pool() -> LockchainResult<()> {
    let tmp = tempdir().unwrap();
    let zfs_path = tmp.path().join("zfs.py");
    fs::write(&zfs_path, FAKE_ZFS_SCRIPT)?;
    make_executable(&zfs_path)?;

    let zpool_path = tmp.path().join("zpool.py");
    fs::write(&zpool_path, FAKE_ZPOOL_SCRIPT)?;
    make_executable(&zpool_path)?;

    let state_path = tmp.path().join("state.json");
    fs::write(&state_path, DEFAULT_STATE)?;

    let _state_guard = EnvGuard::set("FAKE_ZFS_STATE", state_path.to_string_lossy());
    let _health_guard = EnvGuard::set("FAKE_ZPOOL_HEALTH", "ONLINE");

    let key_path = tmp.path().join("usb").join("key.raw");
    fs::create_dir_all(key_path.parent().unwrap())?;
    let raw_key: Vec<u8> = (0..32u8).collect();
    let hex_key = hex::encode(&raw_key);
    fs::write(&key_path, hex_key)?;

    let expected_sha = hex::encode(Sha256::digest(&raw_key));

    let config = Arc::new(LockchainConfig {
        provider: ProviderCfg::default(),
        policy: Policy {
            targets: vec!["tank/secure".to_string(), "tank/secure/home".to_string()],
            binary_path: None,
            allow_root: false,
            legacy_zfs_path: None,
            legacy_zpool_path: None,
        },
        zfs: ZfsCfg {
            zfs_path: Some(zfs_path.to_string_lossy().into_owned()),
            zpool_path: Some(zpool_path.to_string_lossy().into_owned()),
        },
        crypto: CryptoCfg { timeout_secs: 5 },
        luks: LuksCfg::default(),
        usb: Usb {
            key_hex_path: key_path.to_string_lossy().into_owned(),
            expected_sha256: Some(expected_sha),
            ..Usb::default()
        },
        fallback: Fallback {
            enabled: false,
            askpass: false,
            askpass_path: None,
            passphrase_salt: None,
            passphrase_xor: None,
            passphrase_iters: 1,
        },
        retry: RetryCfg::default(),
        path: PathBuf::from("/etc/lockchain.toml"),
        format: ConfigFormat::Toml,
    });

    let provider = SystemZfsProvider::from_config(&config)?;
    let service = LockchainService::new(config.clone(), provider);
    let report = service.unlock("tank/secure", UnlockOptions::default())?;
    assert!(!report.already_unlocked);
    assert!(report.unlocked.contains(&"tank/secure".to_string()));

    // ensure key rewritten to raw bytes with restrictive permissions
    let metadata = fs::metadata(config.key_hex_path())?;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    assert_eq!(fs::read(config.key_hex_path())?, raw_key);
    Ok(())
}

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set<K: Into<String>>(key: &'static str, value: K) -> Self {
        let prev = env::var(key).ok();
        let value = value.into();
        env::set_var(key, &value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(prev) = &self.prev {
            env::set_var(self.key, prev);
        } else {
            env::remove_var(self.key);
        }
    }
}

fn make_executable(path: &Path) -> std::io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
}
