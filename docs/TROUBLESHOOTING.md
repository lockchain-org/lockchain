# Troubleshooting Field Manual

Battle-tested fixes for the most common LockChain hiccups. Every entry includes symptoms, quick checks, and copy/paste remediation commands. Keep logs in JSON for pipelines; flip to plain text if you need to eyeball the signal.

Commands below use the CLI entrypoint `lockchain`. If your environment only exposes the binary as `lockchain-cli`, substitute that name.

This guide currently focuses on the ZFS provider path. LUKS troubleshooting will land alongside ADR-003 follow-ups.

---

## 1) Unlock workflow fails immediately
**Symptoms**
- `lockchain unlock` returns `[LC5001] provider error`
- Systemd units log `Failed to load key` on boot

**Checks**
```bash
# dataset present in policy
grep -A3 '\\[policy\\]' /etc/lockchain.toml

# key file exists and is 0400
ls -l /run/lockchain/key.raw

# consolidated health report
lockchain tuning   # alias: lockchain doctor
```

**Fix**
- Re-seat the USB; confirm `lockchain-key-usb` is active:
  ```bash
  sudo systemctl status lockchain-key-usb.service --no-pager
  ```
- If checksum mismatch, recompute and update config:
  ```bash
  sha256sum /run/lockchain/key.raw
  sudo sed -i 's/^expected_sha256.*/expected_sha256 = "<digest>"/' /etc/lockchain.toml
  ```
- Re-run `lockchain unlock --strict-usb` to verify.

---

## 2) USB key not detected
**Symptoms**
- `lockchain-key-usb` logs show `device ... skipped`
- Tuning warns about missing UUID/label

**Checks**
```bash
udevadm info --query=property --name=/dev/sdX1 | grep -E 'ID_FS_LABEL|ID_FS_UUID'
grep -A6 '\\[usb\\]' /etc/lockchain.toml
journalctl -u lockchain-key-usb.service --since '-5m' --no-pager
```

**Fix**
- Align config with reality (choose one selector):
  ```bash
  sudo sed -i 's|^device_label.*|device_label = "LOCKCHAIN"|; s|^device_uuid.*|# device_uuid = ""|' /etc/lockchain.toml
  ```
- Give slower media more time:
  ```bash
  sudo sed -i 's/^mount_timeout_secs.*/mount_timeout_secs = 20/' /etc/lockchain.toml
  sudo systemctl restart lockchain-key-usb.service
  ```

---

## 3) Self-test cannot build ephemeral pool
**Symptoms**
- `lockchain self-test` emits `[LC5300]` about missing binaries or permissions

**Checks**
```bash
which zfs zpool
lockchain validate -f /etc/lockchain.toml
```

**Fix**
- Install tooling and retry:
  ```bash
  sudo apt-get update && sudo apt-get install -y zfsutils-linux
  lockchain self-test
  ```
- If running as non-root, re-run with `sudo` or grant loop device permissions.

---

## 4) Systemd units report `inactive (dead)`
**Symptoms**
- `systemctl status lockchain.service` shows immediate exit

**Checks**
```bash
journalctl -u lockchain.service --no-pager --since '-10m'
lockchain validate -f /etc/lockchain.toml
```

**Fix**
- Repair units and reload:
  ```bash
  lockchain repair
  sudo systemctl daemon-reload
  sudo systemctl restart lockchain.service lockchain-key-usb.service
  ```
- If config errors persist, run `lockchain tuning` for a guided remediation list.

---

## 5) Break-glass output rejected by `zfs load-key`
**Symptoms**
- `zfs load-key` says `key incorrect` when using the derived emergency key

**Checks**
```bash
grep -A5 '\\[fallback\\]' /etc/lockchain.toml
```
- Ensure both `passphrase_salt` and `passphrase_xor` are populated.

**Fix**
```bash
lockchain breakglass --dataset <pool/dataset> --output /var/lib/lockchain/recovery.key --force
sha256sum /var/lib/lockchain/recovery.key
zfs load-key -L prompt <pool/dataset> < /var/lib/lockchain/recovery.key
```
- If still rejected, rotate fallback material by re-running provisioning in safe mode (`lockchain init --safe`).

---

## 6) Need human-readable logs right now
Switch format temporarily:
```bash
export LOCKCHAIN_LOG_FORMAT=plain
lockchain unlock --strict-usb
```
Revert to JSON afterwards to keep SIEM ingestion clean.

---

## 7) Pools show `DEGRADED` during unlock
**Symptoms**
- Unlock succeeds but logs warn about degraded pool health.

**Checks**
```bash
zpool status
```

**Fix**
- Replace/online the bad vdev; LockChain will keep unlocking while the pool is DEGRADED, but treat it as a maintenance page.

---

## 8) Initramfs loader missing or stale after kernel update
**Symptoms**
- Boot prompts for passphrase even though the USB is present.
- Journald shows `lockchain-load-key` not found or skipped.

**Checks**
```bash
# confirm loader files are baked into initramfs
lsinitramfs /boot/initrd.img-$(uname -r) | grep lockchain || lsinitrd /boot/initramfs-$(uname -r).img | grep lockchain

# audit current integration
lockchain tuning   # rebuilds and validates dracut/initramfs assets
```

**Fix**
- Rebuild and repair assets:
  ```bash
  lockchain tuning       # audits and refreshes loader artifacts
  lockchain repair       # reinstalls/enables mount + unlock units
  sudo reboot            # ensure the new initramfs is used
  ```
- If the loader is still missing, verify dracut/initramfs-tools are installed and re-run `lockchain tuning` with verbose logs (`LOCKCHAIN_LOG_FORMAT=plain`).

---

## 9) Roll back to a previous release
**Symptoms**
- Recent upgrade introduced regressions you need to bypass temporarily.

**Checks**
```bash
lockchain --version || lockchain-cli --version
sudo systemctl status lockchain.service lockchain-key-usb.service --no-pager
```

**Fix**
- Disable services and install the earlier package (replace `<prev>` with the target version):
  ```bash
  sudo systemctl disable --now lockchain.service lockchain-key-usb.service
  sudo apt install ./lockchain-zfs_<prev>_amd64.deb
  sudo systemctl enable --now lockchain.service lockchain-key-usb.service
  ```
- Validate configuration and integration:
  ```bash
  lockchain validate -f /etc/lockchain.toml
  lockchain tuning
  lockchain self-test --strict-usb
  ```
- Keep `/etc/lockchain.toml` and the USB key material intact during rollback; reinstalling does not regenerate keys.

---

If the issue persists, capture the command output, `journalctl -u lockchain-*` snippets, and your `/etc/lockchain.toml` (redact secrets). Open an issue or start a discussion. For security-sensitive findings, follow [`docs/SECURITY.md`](SECURITY.md). Keep the neon low-key, keep the rigor high.
