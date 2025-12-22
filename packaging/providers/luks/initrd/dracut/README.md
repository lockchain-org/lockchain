# dracut assets

Dracut module templates now live under `packaging/dracut/` and are rendered by
LockChain during provisioning/tuning.

Key LUKS files:

- `lockchain-cryptsetup-keys.sh` (mount USB RO, verify checksum, stage keys)
- `lockchain-cryptsetup-keys.service` (initramfs unit)
- `lockchain-cryptsetup-keys.conf` (drop-in for `systemd-cryptsetup@.service`)
