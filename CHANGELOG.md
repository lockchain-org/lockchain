# Changelog // LockChain

> _"Version numbers are just coordinates through space and time."_  

All notable changes to this project will be documented here. The cadence follows semantic versioning once we cross the `v1.x` threshold. Until then we will log every milestone release to keep users updated of what the latest version contains.

## v0.2.1 — LockChain Unified Baseline (14-12-2025)

**Highlights**
- Rebases LockChain as a unified multi-provider workspace (ZFS implemented; LUKS scaffolded).
- Introduces `lockchain-provider` for shared provider contracts, keeping `lockchain-core` focused on workflows.
- Adds `lockchain-luks` crate scaffolding and provider/packaging placeholders for cryptsetup + crypttab + initrd hooks.

**Docs & UX**
- Adds `docs/PROVIDERS.md`, `docs/UI.md`, and ADR-003 for LUKS deployment patterns.
- Refreshes provider architecture notes to reflect the multi-provider layout.

## Legacy (LockChain ZFS lineage)

## v0.2.0-alpha — LockChain Access Ramp (01-12-2025)

**Highlights**
- Added initramfs-tools support alongside dracut with strict `--add lockchain` rebuilds and hard-fail audits to ensure loader assets ship in every image.
- Hardened diagnostics: privilege-aware mounting, reduced log noise for `lockchain-key-usb`, and clearer remediation when tokens are missing or busy.
- Loader fixes for early-boot environments: removed `dirname` dependency, preserved read-only USB handling, and unified checksum/UUID validation across initramfs and the watcher.

**Docs & UX**
- README refreshed with alpha disclaimer, sharper positioning, and a modernised quickstart.
- INSTALL/RELEASE guides updated to the 0.2.0-alpha package coordinates.
- Added `docs/THREAT_MODEL.md` covering attack surface and standards alignment.

## v0.1.9 — Control Deck Ignition (28-10-2025)

- Initial Control Deck (Iced) release with dataset directives for forge, tuning, and unlock.
- USB watcher normalises raw/hex keys and enforces permissions.
- Systemd units for unlock orchestration and CLI/daemon parity on workflows.
