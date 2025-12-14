#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[lockchain] install-systemd.sh must run as root" >&2
  exit 1
fi

SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

if ! getent group lockchain >/dev/null; then
  groupadd --system lockchain
fi
if ! id -u lockchain >/dev/null 2>&1; then
  useradd --system --home /var/lib/lockchain --shell /usr/sbin/nologin \
    --gid lockchain lockchain
fi
install -d -o lockchain -g lockchain /var/lib/lockchain

install -Dm644 "$ROOT_DIR/systemd/run-lockchain.mount" "$SYSTEMD_DIR/run-lockchain.mount"
install -Dm644 "$ROOT_DIR/systemd/lockchain-zfs.service" "$SYSTEMD_DIR/lockchain-zfs.service"
install -Dm644 "$ROOT_DIR/systemd/lockchain-zfs@.service" "$SYSTEMD_DIR/lockchain-zfs@.service"
install -Dm644 "$ROOT_DIR/systemd/lockchain-key-usb.service" "$SYSTEMD_DIR/lockchain-key-usb.service"
install -Dm644 "$ROOT_DIR/systemd/lockchain-luks.service" "$SYSTEMD_DIR/lockchain-luks.service"
install -Dm644 "$ROOT_DIR/systemd/lockchain-luks@.service" "$SYSTEMD_DIR/lockchain-luks@.service"

systemctl daemon-reload
systemctl enable run-lockchain.mount
systemctl enable lockchain-zfs.service
systemctl enable lockchain-key-usb.service

echo "run-lockchain.mount enabled to stage volatile key material."
echo "lockchain-zfs.service enabled under user 'lockchain'."
echo "lockchain-key-usb.service enabled to monitor the USB token."
echo "Enable dataset units with: systemctl enable lockchain-zfs@<dataset>.service"
echo "LUKS units staged (disabled by default): lockchain-luks.service, lockchain-luks@.service"
