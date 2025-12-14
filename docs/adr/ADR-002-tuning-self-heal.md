# ADR-002: Tuning & Self-Heal Sequencing

**Status**: Accepted (Cycle 2025-Q4)  
**Version target**: v0.2.0-alpha

## Context

Early-boot unlocks depend on loader assets, systemd units, and USB state that can drift after upgrades or policy edits. Operators need a single, repeatable workflow (`lockchain tuning` / `lockchain self-heal` / `lockchain doctor`) that inspects and repairs the integration without mutating datasets or key material unexpectedly.

## Forces

- **Early-boot guarantees** — Dracut/initramfs-tools assets must stay in sync with the configured key path and ZFS roots.  
- **Single source of truth** — Keep configuration updates (expected key checksum, USB UUID) authoritative in `/etc/lockchain-zfs.toml`.  
- **Minimal churn** — Only touch what is required to restore readiness; avoid re-forging keys or rewriting datasets.  
- **Deterministic observability** — Emit structured workflow events and sample logs in one pass to reduce operator guesswork.

## Decision

Adopt a unified tuning/self-heal workflow with the following sequencing and boundaries:

1. **Config sanity** — Require at least one dataset; trim/normalise inputs.  
2. **USB hydration** — If the key path lives under the token mount and is missing or the mount is idle, attempt to mount read-only, convert hex→raw if needed, and restore `key.raw`. Warn when label/UUID is unset.  
3. **Key integrity** — Enforce `0400` permissions; compute SHA-256. If `usb.expected_sha256` is empty, persist it. If it differs, emit an error but do not overwrite.  
4. **Keylocation reconciliation** — For each encryption root, set `keylocation=file://…` to the configured path.  
5. **Boot assets** — Reconcile dracut/initramfs assets via `repair_boot_assets`; log warnings on failure instead of silently continuing.  
6. **USB identity hardening** — If label is set but UUID is missing and discoverable, persist the UUID to tighten future matches.  
7. **Service health** — Audit systemd units (`lockchain-zfs.service`, `lockchain-key-usb.service`, dataset units) via `systemctl show`; surface remedies when not loaded/active/enabled.  
8. **Journal sampling** — Tail recent logs for the services, filter noise, and elevate errors/warnings.  
9. **Initramfs tooling presence** — Detect `dracut`/`update-initramfs`; warn if neither is available.  
10. **Keystatus snapshot** — Query provider keystatus for managed datasets to highlight locked descendants.  
11. **Persist minimal config changes** — Save only newly learned `expected_sha256` or USB UUID; never forge new keys or rewrite datasets.

Adjacent command: `lockchain repair` is reserved for reinstalling/enabling systemd units and drop-ins; it should be run after tuning when the report suggests remediation.

## Consequences

**Benefits**
- Single-pass diagnostics avoid duplicate probing across CLI/UI surfaces.  
- Operators get explicit, actionable events for USB state, boot assets, and systemd readiness.  
- Config file captures the authoritative checksum/UUID learned during tuning, reducing future drift.  
- Read-only mounts and narrow repairs reduce risk in early-boot environments.

**Non-goals / Limits**
- No automatic key rotation or dataset mutation.  
- No suppression of provider errors; tuning reports them for operator action.  
- No silent initramfs rebuilds when tooling is absent—warnings guide manual remediation.  
- Rollback/upgrade management stays in packaging docs; tuning does not pin versions.

## Follow-up

- Consider exposing the tuning event stream over the daemon health endpoint for fleet observability.  
- Evaluate optional “strict mode” that fails fast when boot assets cannot be reconciled.  
- Add focused tests around `repair_boot_assets` to guard loader regressions across dracut/initramfs-tools.

— LockChain maintainers
