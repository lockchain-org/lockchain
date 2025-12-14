# Providers

LockChain is a multi-provider unlock orchestration stack. Providers are the only place we touch platform-specific storage APIs (ZFS CLI, `cryptsetup`, etc.); everything else (policy, workflows, CLI/daemon/UI) is shared.

Provider contracts live in `crates/lockchain-provider` so the workflow engine stays focused on orchestration rather than system integration.

---

## Provider Contract

All providers follow the same high-level rules:

- **Deterministic ordering** for listing operations (stable UI tables + predictable tests).
- **Explicit error mapping**: providers return actionable errors with enough context to diagnose missing datasets/devices, permission drift, and CLI failures.
- **No key custody drift**: providers consume raw key bytes supplied by LockChain; they do not invent or persist secrets on their own.

### ZFS Provider Contract

The ZFS provider implements `lockchain_provider::zfs::ZfsProvider` and exposes four deterministic verbs:

- Resolve the encryption root for a dataset.
- List locked descendants under an encryption root.
- Load key material for the encryption root (and descendants).
- Describe keystatus for a dataset list.

### LUKS Provider Contract

The LUKS provider implements `lockchain_provider::luks::LuksProvider` and focuses on:

- Enumerating manageable crypt mappings (usually sourced from crypttab).
- Unlocking mappings via `cryptsetup` using raw key bytes.
- Reporting mapping state for UI/daemon health.

Root unlock adds initrd integration (dracut + initramfs-tools) on top of the provider contract; see ADR-003.

---

## Providers

### `lockchain-zfs` (Implemented)

- Uses native `zfs`/`zpool` binaries.
- Supports delegated permission mode (`zfs allow load-key,key`) or full-root via polkit/sudo (deployment dependent).
- Designed to keep the contract mockable for tests (`unlock_smoke` uses fake binaries).

### `lockchain-luks` (Scaffolded)

- Planned: `cryptsetup` integration + crypttab modelling + initrd hooks.
- Targets both:
  - **Root unlock** via initrd hooks and crypttab patterns.
  - **Non-root unlock** via systemd units and post-boot workflows.

---

## Capability Matrix (Current)

| Capability | `lockchain-zfs` | `lockchain-luks` |
| --- | --- | --- |
| USB key normalisation to `/run/lockchain/` | Yes (shared) | Yes (shared) |
| Unlock non-root volumes post-boot | Yes | Planned |
| Unlock root volume at early boot | Yes (ZFS initrd) | Planned |
| dracut loader assets | Yes | Planned |
| initramfs-tools loader assets | Yes | Planned |
| Control Deck context switching | Planned | Planned |

---

## Configuration Files

LockChain uses a unified config file with provider selection:

- Default: `/etc/lockchain.toml`
- Select provider via `[provider] type = "zfs" | "luks" | "auto"` (`kind` is accepted as a legacy alias).
- Configure targets via `[policy] targets = [...]` (`datasets`, `mappings`, and `volumes` are accepted as legacy aliases).
- Provider-specific sections:
  - ZFS: `[zfs] zfs_path = ...`, `[zfs] zpool_path = ...`
  - LUKS: `[luks] cryptsetup_path = ...`, `[luks] crypttab_path = ...`

Legacy config files are still supported for now (and will be auto-discovered when `/etc/lockchain.toml` is missing):

- ZFS: `/etc/lockchain-zfs.toml` (template: `packaging/systemd/lockchain-zfs.toml`)
- LUKS: `/etc/lockchain-luks.toml` (template: `packaging/systemd/lockchain-luks.toml`)

Example configs:

- Unified template: `packaging/systemd/lockchain.toml`
- ZFS: `docs/examples/lockchain-zfs.toml`
- LUKS: `docs/examples/lockchain-luks.toml`

### Migration Notes

- Preferred path: rename your config to `/etc/lockchain.toml`.
- Key migrations:
  - `provider.kind` → `provider.type` (legacy alias retained)
  - `policy.datasets` / `policy.mappings` → `policy.targets` (legacy aliases retained)
  - `policy.zfs_path` / `policy.zpool_path` → `[zfs] zfs_path` / `[zfs] zpool_path` (legacy keys still accepted)
