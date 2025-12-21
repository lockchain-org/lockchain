//! System-backed `ZfsProvider` implementation. It shells out to the platform
//! binaries, checks the health of pools, and tracks which datasets still need
//! their encryption keys loaded.

use crate::command::{CommandRunner, Output};
use crate::parse::{parse_tabular_pairs, pool_from_dataset};
use lockchain_core::config::LockchainConfig;
use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_provider::zfs::{DatasetKeyDescriptor, KeyState, KeyStatusSnapshot, ZfsProvider};
use log::warn;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default locations we probe when looking for a `zfs` binary on the host.
pub const DEFAULT_ZFS_PATHS: &[&str] = &[
    "/sbin/zfs",
    "/usr/sbin/zfs",
    "/usr/local/sbin/zfs",
    "/bin/zfs",
];

/// Default locations we probe when looking for a `zpool` binary on the host.
pub const DEFAULT_ZPOOL_PATHS: &[&str] = &[
    "/sbin/zpool",
    "/usr/sbin/zpool",
    "/usr/local/sbin/zpool",
    "/bin/zpool",
];

/// System-oriented `ZfsProvider` that shells out to the native `zfs` and `zpool` CLIs.
#[derive(Clone)]
pub struct SystemZfsProvider {
    zfs_runner: CommandRunner,
    zpool_runner: CommandRunner,
}

impl SystemZfsProvider {
    /// Build a provider from the user configuration, falling back to discovery when needed.
    pub fn from_config(config: &LockchainConfig) -> LockchainResult<Self> {
        let timeout = config.zfs_timeout();
        let zfs_runner = if let Some(path) = config.zfs_binary_path() {
            Self::runner_with_path(path, timeout)?
        } else {
            Self::discover_zfs(timeout)?
        };

        let zpool_runner = if let Some(path) = config.zpool_binary_path() {
            Self::runner_with_path(path, timeout)?
        } else {
            Self::discover_zpool(timeout)?
        };

        Ok(Self {
            zfs_runner,
            zpool_runner,
        })
    }

    /// Construct a provider with an explicit `zfs` path and an auto-discovered `zpool`.
    pub fn with_path(path: PathBuf, timeout: Duration) -> LockchainResult<Self> {
        let zfs_runner = Self::runner_with_path(path, timeout)?;
        let zpool_runner = Self::discover_zpool(timeout)?;
        Ok(Self {
            zfs_runner,
            zpool_runner,
        })
    }

    /// Construct a provider with explicit `zfs` and `zpool` binaries.
    pub fn with_paths(
        zfs_path: PathBuf,
        zpool_path: PathBuf,
        timeout: Duration,
    ) -> LockchainResult<Self> {
        let zfs_runner = Self::runner_with_path(zfs_path, timeout)?;
        let zpool_runner = Self::runner_with_path(zpool_path, timeout)?;
        Ok(Self {
            zfs_runner,
            zpool_runner,
        })
    }

    /// Validate that the given path exists and wrap it in a `CommandRunner`.
    fn runner_with_path(path: PathBuf, timeout: Duration) -> LockchainResult<CommandRunner> {
        if !path.exists() {
            return Err(LockchainError::InvalidConfig(format!(
                "binary not found at {}",
                path.display()
            )));
        }
        Ok(CommandRunner::new(path, timeout))
    }

    /// Auto-discover both binaries using the built-in search paths.
    pub fn discover(timeout: Duration) -> LockchainResult<Self> {
        let zfs_runner = Self::discover_zfs(timeout)?;
        let zpool_runner = Self::discover_zpool(timeout)?;
        Ok(Self {
            zfs_runner,
            zpool_runner,
        })
    }

    /// Walk through `DEFAULT_ZFS_PATHS` until a workable binary is found.
    fn discover_zfs(timeout: Duration) -> LockchainResult<CommandRunner> {
        for candidate in DEFAULT_ZFS_PATHS {
            let p = Path::new(candidate);
            if p.exists() {
                return Self::runner_with_path(p.to_path_buf(), timeout);
            }
        }
        Err(LockchainError::InvalidConfig(format!(
            "unable to locate zfs binary; tried {:?}",
            DEFAULT_ZFS_PATHS
        )))
    }

    /// Walk through `DEFAULT_ZPOOL_PATHS` until a workable binary is found.
    fn discover_zpool(timeout: Duration) -> LockchainResult<CommandRunner> {
        for candidate in DEFAULT_ZPOOL_PATHS {
            let p = Path::new(candidate);
            if p.exists() {
                return Self::runner_with_path(p.to_path_buf(), timeout);
            }
        }
        Err(LockchainError::InvalidConfig(format!(
            "unable to locate zpool binary; tried {:?}",
            DEFAULT_ZPOOL_PATHS
        )))
    }

    /// Run `zfs` with arguments and optional stdin payload.
    fn run_zfs(&self, args: &[&str], input: Option<&[u8]>) -> LockchainResult<Output> {
        self.zfs_runner.run(args, input)
    }

    /// Run `zfs` and turn non-zero exits into descriptive provider errors.
    fn run_checked_zfs(&self, args: &[&str]) -> LockchainResult<Output> {
        let out = self.run_zfs(args, None)?;
        if out.status != 0 {
            return Err(Self::classify_cli_error(
                self.zfs_runner.binary(),
                args,
                &out,
            ));
        }
        Ok(out)
    }

    /// Run `zpool` with arguments.
    fn run_zpool(&self, args: &[&str]) -> LockchainResult<Output> {
        self.zpool_runner.run(args, None)
    }

    /// Run `zpool` and surface friendlier errors on failure.
    fn run_checked_zpool(&self, args: &[&str]) -> LockchainResult<Output> {
        let out = self.run_zpool(args)?;
        if out.status != 0 {
            return Err(Self::classify_cli_error(
                self.zpool_runner.binary(),
                args,
                &out,
            ));
        }
        Ok(out)
    }

    /// Map CLI output into a `LockchainError` with context.
    fn classify_cli_error(binary: &Path, args: &[&str], output: &Output) -> LockchainError {
        let stderr = output.stderr.trim();
        let stdout = output.stdout.trim();
        let diagnostic = if !stderr.is_empty() { stderr } else { stdout };
        let diagnostic_lower = diagnostic.to_ascii_lowercase();

        if diagnostic_lower.contains("dataset does not exist")
            || diagnostic_lower.contains("cannot open '")
        {
            return LockchainError::InvalidConfig(format!(
                "{} {} reported missing dataset: {}",
                binary.display(),
                args.join(" "),
                diagnostic
            ));
        }

        if diagnostic_lower.contains("no such pool")
            || diagnostic_lower.contains("pool does not exist")
        {
            return LockchainError::InvalidConfig(format!(
                "{} {} reported missing pool: {}",
                binary.display(),
                args.join(" "),
                diagnostic
            ));
        }

        LockchainError::Provider(format!(
            "{} {} exited with code {}: {}",
            binary.display(),
            args.join(" "),
            output.status,
            if diagnostic.is_empty() {
                "no additional output"
            } else {
                diagnostic
            }
        ))
    }

    /// Confirm the pool exists and reports a healthy status.
    fn ensure_pool_ready(&self, pool: &str) -> LockchainResult<()> {
        let args = ["list", "-H", "-o", "name,health", pool];
        let out = self.run_checked_zpool(&args)?;

        let mut seen = false;
        let mut reported_health: Option<String> = None;
        for (name, health) in parse_tabular_pairs(&out.stdout) {
            if name == pool {
                seen = true;
                reported_health = Some(health);
            }
        }

        if !seen {
            return Err(LockchainError::Provider(format!(
                "pool {} not reported by zpool list output",
                pool
            )));
        }

        if let Some(health) = reported_health {
            let lowered = health.to_ascii_lowercase();
            if lowered == "online" {
                return Ok(());
            }
            if lowered == "degraded" {
                warn!(
                    "pool {} reports degraded health; continuing unlock workflows",
                    pool
                );
                return Ok(());
            }
            return Err(LockchainError::Provider(format!(
                "pool {} is not healthy (reported state: {})",
                pool, health
            )));
        }

        Ok(())
    }

    /// Ensure we can resolve the dataset's pool and that the pool is healthy.
    fn ensure_dataset_pool_ready(&self, dataset: &str) -> LockchainResult<()> {
        let pool = pool_from_dataset(dataset).ok_or_else(|| {
            LockchainError::InvalidConfig(format!(
                "dataset `{}` does not map to a valid pool name",
                dataset
            ))
        })?;
        self.ensure_pool_ready(pool)
    }

    /// Fetch a single `zfs get` property value.
    fn get_property(&self, dataset: &str, property: &str) -> LockchainResult<String> {
        let out = self.run_checked_zfs(&["get", "-H", "-o", "value", property, dataset])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Try to load the dataset key, ignoring the benign "already loaded" warning.
    fn load_key(&self, dataset: &str, key: &[u8]) -> LockchainResult<()> {
        let args = ["load-key", "-L", "prompt", dataset];
        let out = self.run_zfs(&args, Some(key))?;
        if out.status != 0 {
            let diagnostic = if !out.stderr.trim().is_empty() {
                out.stderr.trim()
            } else {
                out.stdout.trim()
            };
            if diagnostic.contains("Key already loaded") {
                return Ok(());
            }
            return Err(Self::classify_cli_error(
                self.zfs_runner.binary(),
                &args,
                &out,
            ));
        }
        Ok(())
    }

    /// Ask `zfs` for the dataset's `keystatus` and translate it to `KeyState`.
    ///
    /// `parse_keystatus` stays separate so tests can validate the string mapping in isolation.
    fn keystatus(&self, dataset: &str) -> LockchainResult<KeyState> {
        let out = self.run_checked_zfs(&["get", "-H", "-o", "value", "keystatus", dataset])?;
        Ok(Self::parse_keystatus(out.stdout.trim()))
    }

    /// Translate the raw `keystatus` field into `KeyState`.
    fn parse_keystatus(value: &str) -> KeyState {
        match value {
            "available" => KeyState::Available,
            "unavailable" | "absent" | "missing" => KeyState::Unavailable,
            other if other.is_empty() || other == "-" || other == "none" => {
                KeyState::Unknown(other.to_string())
            }
            other => KeyState::Unknown(other.to_string()),
        }
    }
}

impl ZfsProvider for SystemZfsProvider {
    type Error = LockchainError;

    /// Ask `zfs` for the dataset's `encryptionroot` property.
    fn encryption_root(&self, dataset: &str) -> LockchainResult<String> {
        self.get_property(dataset, "encryptionroot")
    }

    /// List every descendant under `root` that still reports a locked key.
    fn locked_descendants(&self, root: &str) -> LockchainResult<Vec<String>> {
        self.ensure_dataset_pool_ready(root)?;

        let list_output =
            self.run_checked_zfs(&["list", "-H", "-r", "-o", "name,encryptionroot", root])?;
        let same_root: HashSet<String> = parse_tabular_pairs(&list_output.stdout)
            .into_iter()
            .filter(|(_, enc_root)| enc_root == root)
            .map(|(name, _)| name)
            .collect();

        let status_output =
            self.run_checked_zfs(&["get", "-H", "-r", "-o", "name,value", "keystatus", root])?;
        let mut locked = Vec::new();
        for (name, value) in parse_tabular_pairs(&status_output.stdout) {
            if same_root.contains(&name) {
                let state = Self::parse_keystatus(value.trim());
                if !matches!(state, KeyState::Available) {
                    locked.push(name);
                }
            }
        }
        locked.sort_unstable();
        Ok(locked)
    }

    /// Load the key at `root`, retry locked descendants, and surface any stragglers.
    fn load_key_tree(&self, root: &str, key: &[u8]) -> LockchainResult<Vec<String>> {
        self.ensure_dataset_pool_ready(root)?;
        self.load_key(root, key)?;
        let mut unlocked = vec![root.to_string()];

        let pending = self
            .locked_descendants(root)?
            .into_iter()
            .filter(|ds| ds != root)
            .collect::<Vec<_>>();
        for ds in &pending {
            self.load_key(ds, key)?;
            unlocked.push(ds.clone());
        }

        let stubborn = self.locked_descendants(root)?;
        if stubborn.iter().any(|ds| ds == root) {
            return Err(LockchainError::Provider(format!(
                "encryption root {} remained locked after load-key",
                root
            )));
        }
        let stubborn_descendants: Vec<String> =
            stubborn.into_iter().filter(|ds| ds != root).collect();
        if !stubborn_descendants.is_empty() {
            return Err(LockchainError::Provider(format!(
                "descendants still locked after retries: {}",
                stubborn_descendants.join(", ")
            )));
        }

        Ok(unlocked)
    }

    /// Describe the current key status for each dataset listed by the caller.
    fn describe_datasets(&self, datasets: &[String]) -> LockchainResult<KeyStatusSnapshot> {
        let mut snapshot = Vec::with_capacity(datasets.len());
        let mut checked_pools = HashSet::new();

        for ds in datasets {
            let pool = pool_from_dataset(ds).ok_or_else(|| {
                LockchainError::InvalidConfig(format!(
                    "dataset `{}` does not map to a valid pool name",
                    ds
                ))
            })?;

            if checked_pools.insert(pool.to_string()) {
                self.ensure_pool_ready(pool)?;
            }

            let encryption_root = self.encryption_root(ds)?;
            let state = self.keystatus(ds)?;
            snapshot.push(DatasetKeyDescriptor {
                dataset: ds.clone(),
                encryption_root,
                state,
            });
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keystatus_handles_basic_cases() {
        assert!(matches!(
            SystemZfsProvider::parse_keystatus("available"),
            KeyState::Available
        ));
        assert!(matches!(
            SystemZfsProvider::parse_keystatus("unavailable"),
            KeyState::Unavailable
        ));
        assert!(matches!(
            SystemZfsProvider::parse_keystatus(""),
            KeyState::Unknown(_)
        ));
    }

    #[cfg(unix)]
    mod integration {
        use super::*;
        use lockchain_core::error::{LockchainError, LockchainResult};
        use std::env;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::sync::{Mutex, OnceLock};
        use std::time::Duration;
        use tempfile::{tempdir, TempDir};

        const DEFAULT_STATE: &str =
            r#"{"tank/secure":"unavailable","tank/secure/home":"unavailable"}"#;
        const AVAILABLE_STATE: &str =
            r#"{"tank/secure":"available","tank/secure/home":"available"}"#;

        const FAKE_ZFS_SCRIPT: &str = r#"#!/usr/bin/env python3
import json
import os
import sys

STATE_PATH = os.environ.get("FAKE_ZFS_STATE")
if not STATE_PATH:
    print("FAKE_ZFS_STATE not set", file=sys.stderr)
    sys.exit(3)

try:
    with open(STATE_PATH, "r", encoding="utf-8") as fh:
        state = json.load(fh)
except FileNotFoundError:
    state = {}
except json.JSONDecodeError:
    state = {}

def known_datasets():
    if state:
        return list(state.keys())
    return ["tank/secure", "tank/secure/home"]

def save():
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)

def ensure_dataset_known(dataset):
    if dataset not in known_datasets():
        print(f"cannot open '{dataset}': dataset does not exist", file=sys.stderr)
        sys.exit(1)

def dataset_children(root):
    return [name for name in known_datasets() if name == root or name.startswith(root + "/")]

args = sys.argv[1:]
if not args:
    sys.exit(2)

if args[0] == "list" and len(args) >= 6 and args[1] == "-H" and args[2] == "-r" and args[3] == "-o" and args[4] == "name,encryptionroot":
    root = args[5]
    ensure_dataset_known(root)
    for name in dataset_children(root):
        print(f"{name}\t{root}")
    sys.exit(0)

if args[0] == "get" and len(args) >= 7 and args[1] == "-H" and args[2] == "-r" and args[3] == "-o" and args[4] == "name,value" and args[5] == "keystatus":
    root = args[6]
    ensure_dataset_known(root)
    for name in dataset_children(root):
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
    print(dataset)
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
import json
import os
import sys

def resolve_health(pool):
    raw = os.environ.get("FAKE_ZPOOL_HEALTH", "ONLINE")
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        mapping = None

    if isinstance(mapping, dict):
        default = mapping.get("_default", "ONLINE")
        return mapping.get(pool, default)
    return raw

args = sys.argv[1:]
if len(args) >= 5 and args[0] == "list" and args[1] == "-H" and args[2] == "-o" and args[3] == "name,health":
    pool = args[4]
    health = resolve_health(pool)
    if health is None:
        print(f"cannot open '{pool}': no such pool", file=sys.stderr)
        sys.exit(1)
    print(f"{pool}\t{health}")
    sys.exit(0)

print("unexpected args: " + " ".join(args), file=sys.stderr)
sys.exit(2)
"#;

        struct EnvGuard {
            key: &'static str,
            prev: Option<String>,
        }

        impl EnvGuard {
            fn set(key: &'static str, value: impl Into<String>) -> Self {
                let prev = env::var(key).ok();
                env::set_var(key, value.into());
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

        struct ProviderFixture {
            provider: SystemZfsProvider,
            _tmp: TempDir,
            _state_guard: EnvGuard,
            _health_guard: EnvGuard,
        }

        impl ProviderFixture {
            fn new(health: &str, state: &str) -> LockchainResult<Self> {
                let tmp = tempdir()?;
                let zfs_path = tmp.path().join("zfs.py");
                fs::write(&zfs_path, FAKE_ZFS_SCRIPT)?;
                make_executable(&zfs_path)?;
                let zpool_path = tmp.path().join("zpool.py");
                fs::write(&zpool_path, FAKE_ZPOOL_SCRIPT)?;
                make_executable(&zpool_path)?;
                let state_path = tmp.path().join("state.json");
                fs::write(&state_path, state)?;
                let state_guard =
                    EnvGuard::set("FAKE_ZFS_STATE", state_path.to_string_lossy().into_owned());
                let health_guard = EnvGuard::set("FAKE_ZPOOL_HEALTH", health.to_string());
                let provider =
                    SystemZfsProvider::with_paths(zfs_path, zpool_path, Duration::from_secs(2))?;
                Ok(Self {
                    provider,
                    _tmp: tmp,
                    _state_guard: state_guard,
                    _health_guard: health_guard,
                })
            }

            fn provider(&self) -> &SystemZfsProvider {
                &self.provider
            }
        }

        fn make_executable(path: &Path) -> std::io::Result<()> {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms)
        }

        fn test_lock() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
        }

        #[test]
        fn load_key_tree_unlocks_datasets() {
            let _guard = test_lock();
            let fixture = ProviderFixture::new("ONLINE", DEFAULT_STATE).unwrap();
            let provider = fixture.provider();

            let initial = provider.locked_descendants("tank/secure").unwrap();
            assert_eq!(
                initial,
                vec!["tank/secure".to_string(), "tank/secure/home".to_string()]
            );

            let key = vec![0u8; 32];
            let unlocked = provider.load_key_tree("tank/secure", &key).unwrap();
            assert_eq!(
                unlocked,
                vec!["tank/secure".to_string(), "tank/secure/home".to_string()]
            );

            let after = provider.locked_descendants("tank/secure").unwrap();
            assert!(after.is_empty());
        }

        #[test]
        fn locked_descendants_missing_dataset_returns_invalid_config() {
            let _guard = test_lock();
            let fixture = ProviderFixture::new("ONLINE", DEFAULT_STATE).unwrap();
            let err = fixture
                .provider()
                .locked_descendants("tank/missing")
                .unwrap_err();
            match err {
                LockchainError::InvalidConfig(msg) => {
                    assert!(msg.contains("dataset does not exist"), "{}", msg);
                }
                other => panic!("expected InvalidConfig, got {:?}", other),
            }
        }

        #[test]
        fn locked_descendants_warns_but_allows_degraded_pool() {
            let _guard = test_lock();
            let fixture = ProviderFixture::new("DEGRADED", DEFAULT_STATE).unwrap();
            let locked = fixture
                .provider()
                .locked_descendants("tank/secure")
                .unwrap();
            assert!(
                locked.contains(&"tank/secure".to_string()),
                "expected root to remain locked until load-key"
            );
        }

        #[test]
        fn locked_descendants_fails_when_pool_faulted() {
            let _guard = test_lock();
            let fixture = ProviderFixture::new("FAULTED", DEFAULT_STATE).unwrap();
            let err = fixture
                .provider()
                .locked_descendants("tank/secure")
                .unwrap_err();
            match err {
                LockchainError::Provider(msg) => {
                    assert!(msg.contains("not healthy"), "{}", msg);
                }
                other => panic!("expected Provider error, got {:?}", other),
            }
        }

        #[test]
        fn describe_datasets_reports_available_state() {
            let _guard = test_lock();
            let fixture = ProviderFixture::new("ONLINE", AVAILABLE_STATE).unwrap();
            let snapshot = fixture
                .provider()
                .describe_datasets(&["tank/secure".to_string()])
                .unwrap();
            assert_eq!(snapshot.len(), 1);
            assert_eq!(snapshot[0].dataset, "tank/secure");
            assert_eq!(snapshot[0].encryption_root, "tank/secure");
            assert!(matches!(snapshot[0].state, KeyState::Available));
        }

        #[test]
        fn describe_datasets_handles_multiple_pools_and_degraded_health() {
            let _guard = test_lock();
            let multi_state = r#"{"tank/secure":"available","bunker/crypt":"unavailable","bunker/crypt/data":"unavailable"}"#;
            let health = r#"{"tank":"ONLINE","bunker":"DEGRADED"}"#;
            let fixture = ProviderFixture::new(health, multi_state).unwrap();
            let snapshot = fixture
                .provider()
                .describe_datasets(&["tank/secure".to_string(), "bunker/crypt".to_string()])
                .unwrap();
            assert_eq!(snapshot.len(), 2);
            assert_eq!(snapshot[0].dataset, "tank/secure");
            assert_eq!(snapshot[0].encryption_root, "tank/secure");
            assert!(matches!(snapshot[0].state, KeyState::Available));
            assert_eq!(snapshot[1].dataset, "bunker/crypt");
            assert_eq!(snapshot[1].encryption_root, "bunker/crypt");
            assert!(matches!(snapshot[1].state, KeyState::Unavailable));
        }
    }
}
