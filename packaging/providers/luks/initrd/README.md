# LUKS initrd assets

This directory is reserved for provider-specific early-boot integration assets for the
`lockchain-luks` provider (ADR-003).

Status:

- dracut module templates: `packaging/dracut/`
- initramfs-tools hooks/scripts (pending)
- keyscript helpers for `cryptsetup` + `/etc/crypttab` (pending)
