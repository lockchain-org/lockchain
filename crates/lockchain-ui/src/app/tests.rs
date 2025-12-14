use super::*;
use lockchain_core::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, LuksCfg, Policy, ProviderCfg, RetryCfg,
    Usb, ZfsCfg,
};
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn parse_kv_splits_pairs_and_free_args() {
    let (kv, free) = parse_kv("dataset=tank/secure passphrase=secret dry-run extra");
    assert_eq!(kv.get("dataset").unwrap(), "tank/secure");
    assert_eq!(kv.get("passphrase").unwrap(), "secret");
    assert!(!kv.contains_key("dry-run"));
    assert_eq!(free, vec!["dry-run", "extra"]);
}

#[test]
fn parse_bool_accepts_common_truthy_values() {
    for truthy in ["1", "true", "YES", "On"] {
        assert!(parse_bool(truthy));
    }
    for falsy in ["0", "false", "no", "off", "maybe"] {
        assert!(!parse_bool(falsy));
    }
}

#[test]
fn resolve_dataset_prefers_command_line_values() {
    let mut config = dummy_config();
    config.policy.targets = vec!["tank/secure".into()];

    let mut kv = HashMap::new();
    kv.insert("dataset".to_string(), "tank/alt".to_string());
    let dataset = resolve_dataset(&config, &kv, &[]);
    assert_eq!(dataset.unwrap(), "tank/alt");
}

fn dummy_config() -> LockchainConfig {
    LockchainConfig {
        provider: ProviderCfg::default(),
        policy: Policy {
            targets: vec![],
            binary_path: None,
            allow_root: false,
            legacy_zfs_path: None,
            legacy_zpool_path: None,
        },
        zfs: ZfsCfg::default(),
        crypto: CryptoCfg { timeout_secs: 5 },
        luks: LuksCfg::default(),
        usb: Usb {
            key_hex_path: "/tmp/key.raw".into(),
            expected_sha256: None,
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
        path: PathBuf::from("/tmp/config"),
        format: ConfigFormat::Toml,
    }
}
