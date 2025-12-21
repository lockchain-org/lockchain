use lockchain_core::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, LuksCfg, Policy, ProviderCfg, RetryCfg,
    Usb, ZfsCfg,
};
use lockchain_core::error::LockchainResult;
use lockchain_core::provider::ProviderKind;
use lockchain_luks::SystemLuksProvider;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl Into<std::ffi::OsString>) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value.into());
        Self { key, prev }
    }

    fn unset(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.prev.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn write_executable(path: &Path, contents: &str) -> LockchainResult<()> {
    fs::write(path, contents)?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn base_luks_config(key_hex_path: PathBuf, cryptsetup_path: PathBuf) -> LockchainConfig {
    LockchainConfig {
        provider: ProviderCfg {
            r#type: ProviderKind::Luks,
        },
        policy: Policy {
            targets: vec!["vault".to_string()],
            binary_path: None,
            allow_root: false,
            legacy_zfs_path: None,
            legacy_zpool_path: None,
        },
        zfs: ZfsCfg::default(),
        crypto: CryptoCfg { timeout_secs: 5 },
        luks: LuksCfg {
            cryptsetup_path: Some(cryptsetup_path.to_string_lossy().into_owned()),
            crypttab_path: None,
        },
        usb: Usb {
            key_hex_path: key_hex_path.to_string_lossy().into_owned(),
            ..Usb::default()
        },
        fallback: Fallback::default(),
        retry: RetryCfg::default(),
        path: PathBuf::from("/etc/lockchain.toml"),
        format: ConfigFormat::Toml,
    }
}

#[test]
fn workflow_self_test_luks_runs_and_cleans_up() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir)?;

    let losetup_log = tmp.path().join("losetup.log");
    let losetup_path = bin_dir.join("losetup");
    write_executable(
        &losetup_path,
        &format!(
            r#"#!/bin/sh
LOG="{log}"
if [ "$1" = "--find" ] && [ "$2" = "--show" ]; then
  echo "attach $3" >> "$LOG"
  echo "/dev/loop999"
  exit 0
fi
if [ "$1" = "-d" ]; then
  echo "detach $2" >> "$LOG"
  exit 0
fi
echo "unsupported $*" >> "$LOG"
exit 1
"#,
            log = losetup_log.display()
        ),
    )?;

    let cryptsetup_state = tmp.path().join("cryptsetup-state");
    let cryptsetup_log = tmp.path().join("cryptsetup.log");
    let cryptsetup_path = bin_dir.join("cryptsetup");
    write_executable(
        &cryptsetup_path,
        &format!(
            r#"#!/bin/sh
STATE_DIR="{state_dir}"
LOG="{log}"
PASSFILE="$STATE_DIR/passphrase"
SLOTS_DIR="$STATE_DIR/slots"
ACTIVE="$STATE_DIR/active"

mkdir -p "$STATE_DIR" "$SLOTS_DIR" 2>/dev/null || true

cmd="$1"
shift
echo "$cmd $*" >> "$LOG"

case "$cmd" in
  luksFormat)
    KEYFILE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --type) shift 2 ;;
        --batch-mode) shift ;;
        --key-file) KEYFILE="$2"; shift 2 ;;
        --key-file=*) KEYFILE="${{1#--key-file=}}"; shift ;;
        *) break ;;
      esac
    done
    DEV="$1"
    PASSPHRASE="$(cat)"
    printf "%s" "$PASSPHRASE" > "$PASSFILE"
    rm -f "$SLOTS_DIR"/slot* 2>/dev/null || true
    exit 0
    ;;
  luksAddKey)
    KEYFILE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --batch-mode) shift ;;
        --key-file) KEYFILE="$2"; shift 2 ;;
        --key-file=*) KEYFILE="${{1#--key-file=}}"; shift ;;
        *) break ;;
      esac
    done
    DEV="$1"
    NEW_KEY="$2"
    PASSPHRASE="$(cat)"
    PASSPHRASE="$(printf "%s" "$PASSPHRASE" | tr -d '\n')"
    EXPECTED="$(cat "$PASSFILE" 2>/dev/null || true)"
    EXPECTED="$(printf "%s" "$EXPECTED" | tr -d '\n')"
    if [ "$PASSPHRASE" != "$EXPECTED" ]; then
      echo "No key available with this passphrase." 1>&2
      exit 2
    fi
    IDX=1
    while [ -f "$SLOTS_DIR/slot$IDX" ]; do IDX=$((IDX+1)); done
    cp "$NEW_KEY" "$SLOTS_DIR/slot$IDX" 2>/dev/null || true
    echo "Key slot added"
    exit 0
    ;;
  open|luksOpen)
    KEYFILE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --key-file) KEYFILE="$2"; shift 2 ;;
        --key-file=*) KEYFILE="${{1#--key-file=}}"; shift ;;
        --batch-mode) shift ;;
        --type) shift 2 ;;
        *) break ;;
      esac
    done
    DEV="$1"
    NAME="$2"
    MATCH=0
    for SLOT in "$SLOTS_DIR"/slot*; do
      if [ -f "$SLOT" ] && cmp -s "$KEYFILE" "$SLOT"; then
        MATCH=1
        break
      fi
    done
    if [ "$MATCH" -ne 1 ]; then
      echo "No key available with this passphrase." 1>&2
      exit 2
    fi
    if [ -f "$ACTIVE" ]; then
      grep -v "^$NAME=" "$ACTIVE" > "$ACTIVE.tmp" 2>/dev/null || true
      mv "$ACTIVE.tmp" "$ACTIVE"
    fi
    echo "$NAME=active" >> "$ACTIVE"
    exit 0
    ;;
  close|luksClose)
    NAME="$1"
    if [ -f "$ACTIVE" ]; then
      grep -v "^$NAME=" "$ACTIVE" > "$ACTIVE.tmp" 2>/dev/null || true
      mv "$ACTIVE.tmp" "$ACTIVE"
    fi
    exit 0
    ;;
  status)
    NAME="$1"
    if [ -f "$ACTIVE" ] && grep -q "^$NAME=active$" "$ACTIVE"; then
      echo "/dev/mapper/$NAME is active"
      exit 0
    fi
    echo "/dev/mapper/$NAME is inactive"
    exit 4
    ;;
  *)
    echo "unsupported" 1>&2
    exit 1
    ;;
esac
"#,
            state_dir = cryptsetup_state.display(),
            log = cryptsetup_log.display()
        ),
    )?;

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let combined = format!("{}:{}", bin_dir.display(), old_path.to_string_lossy());
    let _path_guard = EnvGuard::set("PATH", combined);
    let _key_guard = EnvGuard::unset("LOCKCHAIN_KEY_PATH");

    let key_path = tmp.path().join("key.raw");
    let key_bytes = vec![0xAA; 32];
    fs::write(&key_path, &key_bytes)?;

    let mut config = base_luks_config(key_path.clone(), cryptsetup_path.clone());
    config.usb.expected_sha256 = Some(hex::encode(Sha256::digest(&key_bytes)));

    let report = lockchain_core::workflow::self_test_luks(
        &config,
        SystemLuksProvider::from_config,
        "vault",
        true,
    )?;

    assert_eq!(report.title, "Self-test vault simulation");

    let losetup_log_contents = fs::read_to_string(&losetup_log).unwrap_or_default();
    assert!(
        losetup_log_contents.contains("detach /dev/loop999"),
        "expected loop device to be detached, log: {losetup_log_contents}"
    );

    let active_path = cryptsetup_state.join("active");
    if active_path.exists() {
        let active = fs::read_to_string(active_path).unwrap_or_default();
        assert!(
            active.trim().is_empty(),
            "expected no active mappings after self-test, got: {active}"
        );
    }

    Ok(())
}
