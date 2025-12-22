#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[lockchain] install-systemd.sh must run as root" >&2
  exit 1
fi

log() {
  echo "[lockchain] $*"
}

warn() {
  echo "[lockchain] warning: $*" >&2
}

INITRAMFS_TOOL=""
INITRAMFS_DRACUT_PATH=""
INITRAMFS_UPDATE_PATH=""

resolve_initramfs_tool() {
  INITRAMFS_DRACUT_PATH=$(command -v dracut 2>/dev/null || true)
  INITRAMFS_UPDATE_PATH=$(command -v update-initramfs 2>/dev/null || true)

  if [[ -n "$INITRAMFS_DRACUT_PATH" ]]; then
    INITRAMFS_TOOL="dracut"
    if [[ -n "$INITRAMFS_UPDATE_PATH" ]]; then
      log "Initramfs tooling detected: dracut ($INITRAMFS_DRACUT_PATH) and update-initramfs ($INITRAMFS_UPDATE_PATH); preferring dracut."
    else
      log "Initramfs tooling detected: dracut ($INITRAMFS_DRACUT_PATH)."
    fi
  elif [[ -n "$INITRAMFS_UPDATE_PATH" ]]; then
    INITRAMFS_TOOL="initramfs-tools"
    log "Initramfs tooling detected: update-initramfs ($INITRAMFS_UPDATE_PATH)."
  else
    INITRAMFS_TOOL=""
    warn "Initramfs tooling not detected (dracut/update-initramfs missing)."
  fi
}

initramfs_rollback_hint() {
  local tool="$1"
  case "$tool" in
    dracut)
      log "Rollback (dracut): rm -rf /usr/lib/dracut/modules.d/90lockchain /lib/dracut/modules.d/90lockchain"
      log "Rollback (dracut): dracut -f"
      ;;
    initramfs-tools)
      log "Rollback (initramfs-tools): rm -f /etc/initramfs-tools/hooks/zz-lockchain /etc/initramfs-tools/scripts/local-top/lockchain /etc/initramfs-tools/scripts/init-top/00-lockchain-cryptsetup-keys"
      log "Rollback (initramfs-tools): update-initramfs -u"
      ;;
    *)
      log "Rollback: remove LockChain initramfs assets and rebuild your initramfs image."
      ;;
  esac
}

rebuild_initramfs() {
  local tool="$1"
  case "$tool" in
    dracut)
      if [[ -d /usr/lib/dracut/modules.d/90lockchain || -d /lib/dracut/modules.d/90lockchain ]]; then
        dracut -f --add lockchain
        return $?
      fi
      warn "dracut module not found; run lockchain-cli init or tuning to install boot assets."
      return 1
      ;;
    initramfs-tools)
      if [[ -f /etc/initramfs-tools/hooks/zz-lockchain ]]; then
        update-initramfs -u
        return $?
      fi
      warn "initramfs-tools hooks not found; run lockchain-cli init or tuning to install boot assets."
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

install_initramfs_integration() {
  resolve_initramfs_tool
  if [[ -z "$INITRAMFS_TOOL" ]]; then
    warn "Skipping initramfs integration (no tooling detected)."
    return
  fi

  if [[ ${SKIP_INITRAMFS:-0} -eq 1 ]]; then
    log "Initramfs integration skipped (SKIP_INITRAMFS=1)."
    initramfs_rollback_hint "$INITRAMFS_TOOL"
    return
  fi

  local cli="${LOCKCHAIN_CLI:-}"
  if [[ -z "$cli" ]]; then
    cli=$(command -v lockchain-cli 2>/dev/null || true)
  fi

  if [[ -n "$cli" && -x "$cli" && -f "$CONFIG_PATH" ]]; then
    log "Installing boot assets via lockchain-cli tuning (config: $CONFIG_PATH)."
    if ! LOCKCHAIN_CONFIG="$CONFIG_PATH" "$cli" tuning; then
      warn "lockchain-cli tuning failed; attempting direct initramfs rebuild if assets exist."
    fi
  else
    warn "lockchain-cli or config not found; skipping tuning step."
  fi

  if rebuild_initramfs "$INITRAMFS_TOOL"; then
    log "Initramfs rebuild complete."
  else
    warn "Initramfs rebuild skipped or failed; see rollback hints."
  fi

  initramfs_rollback_hint "$INITRAMFS_TOOL"
}

SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
PACKAGING_DIR="$ROOT_DIR/packaging"
SYSTEMD_SOURCE="$PACKAGING_DIR/systemd"
CONFIG_PATH=${CONFIG_PATH:-/etc/lockchain.toml}
LOCKCHAIN_CLI=${LOCKCHAIN_CLI:-}

if ! getent group lockchain >/dev/null; then
  groupadd --system lockchain
fi
if ! id -u lockchain >/dev/null 2>&1; then
  useradd --system --home /var/lib/lockchain --shell /usr/sbin/nologin \
    --gid lockchain lockchain
fi
install -d -o lockchain -g lockchain /var/lib/lockchain

install -Dm644 "$SYSTEMD_SOURCE/run-lockchain.mount" "$SYSTEMD_DIR/run-lockchain.mount"
install -Dm644 "$SYSTEMD_SOURCE/lockchain.service" "$SYSTEMD_DIR/lockchain.service"
install -Dm644 "$SYSTEMD_SOURCE/lockchain@.service" "$SYSTEMD_DIR/lockchain@.service"
install -Dm644 "$SYSTEMD_SOURCE/lockchain-key-usb.service" "$SYSTEMD_DIR/lockchain-key-usb.service"

# Legacy unit names (installed for compatibility; prefer lockchain.service).
install -Dm644 "$PACKAGING_DIR/providers/zfs/systemd/lockchain-zfs.service" "$SYSTEMD_DIR/lockchain-zfs.service"
install -Dm644 "$PACKAGING_DIR/providers/zfs/systemd/lockchain-zfs@.service" "$SYSTEMD_DIR/lockchain-zfs@.service"
install -Dm644 "$PACKAGING_DIR/providers/luks/systemd/lockchain-luks.service" "$SYSTEMD_DIR/lockchain-luks.service"
install -Dm644 "$PACKAGING_DIR/providers/luks/systemd/lockchain-luks@.service" "$SYSTEMD_DIR/lockchain-luks@.service"

systemctl daemon-reload
systemctl enable run-lockchain.mount
systemctl enable lockchain.service
systemctl enable lockchain-key-usb.service

install_initramfs_integration

echo "run-lockchain.mount enabled to stage volatile key material."
echo "lockchain.service enabled under user 'lockchain'."
echo "lockchain-key-usb.service enabled to monitor the USB token."
echo "Enable unlock units with: systemctl enable lockchain@<target>.service"
echo "Legacy unit names also installed: lockchain-zfs.service, lockchain-luks.service"
