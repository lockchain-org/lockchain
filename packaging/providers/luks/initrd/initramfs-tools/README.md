# initramfs-tools assets

LockChain installs initramfs-tools hooks/scripts during provisioning or tuning.
Generated paths:

- `/etc/initramfs-tools/hooks/zz-lockchain` (copies required binaries)
- `/etc/initramfs-tools/scripts/local-top/lockchain` (ZFS auto-unlock)
- `/etc/initramfs-tools/scripts/init-top/00-lockchain-cryptsetup-keys` (LUKS key staging)

The LUKS init-top script mounts the USB token read-only, verifies UUID/checksum,
and stages keys into `/run/cryptsetup-keys.d/<mapping>.key`.

Validation checklist:

- Ensure initramfs-tools is installed and dracut is absent.
- Run `lockchain tuning` (or `lockchain repair`) to install hooks.
- Confirm assets in the image with `lsinitramfs /boot/initrd.img-$(uname -r) | rg 'lockchain|cryptsetup-keys'`.
- Rebuild with `update-initramfs -u`, reboot, and confirm unlock uses staged keys.
