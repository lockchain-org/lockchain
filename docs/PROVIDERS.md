# Providers

LockChain is a multi-provider unlock orchestration stack. Providers are the only place we touch platform-specific storage APIs (ZFS CLI, `cryptsetup`, etc.); everything else (policy, workflows, CLI/daemon/UI) is shared.

Provider contracts live in `crates/lockchain-provider`, and `lockchain-core` adapts them into a single workflow boundary so ZFS datasets and LUKS mappings can share unlock/status workflows without duplicating orchestration logic.

---

## Provider Contract

LockChain uses two layers of contracts:

1. **Provider-native traits** in `crates/lockchain-provider` (`ZfsProvider`, `LuksProvider`).
2. **Unified workflow trait** in `crates/lockchain-core` (`KeyProvider`) that the rest of the stack depends on.

All providers follow the same high-level rules:

- **Deterministic ordering** for listing operations (stable UI tables + predictable tests).
- **Explicit error mapping**: providers return actionable errors with enough context to diagnose missing datasets/devices, permission drift, and CLI failures.
- **No key custody drift**: providers consume raw key bytes supplied by LockChain; they do not invent or persist secrets on their own.

### Unified Workflow Contract (`KeyProvider`)

`lockchain-core` speaks one contract. Providers either implement it directly (ZFS) or are adapted to it (LUKS).

```rust
pub trait KeyProvider {
    type Error;
    fn kind(&self) -> ProviderKind;
    fn encryption_root(&self, target: &str) -> Result<String, Self::Error>;
    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error>;
    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error>;
    fn describe_targets(&self, targets: &[String]) -> Result<KeyStatusSnapshot, Self::Error>;
}
```

Interpretation:

- For **ZFS**, `target` is a dataset and `encryption_root()` may return a different dataset (the encryption root).
- For **LUKS**, `target` is a crypt mapping name; the “root” is the mapping itself.
- `locked_descendants()` must include `root` when it is still sealed/inactive (this is how workflows determine “already unlocked”).
- `describe_targets()` returns the shared “key available/unavailable” snapshot used by `list-keys` and UI tables; LUKS projects mapping state into the same shape.

### ZFS Provider Contract (`ZfsProvider`)

The ZFS provider implements `lockchain_provider::zfs::ZfsProvider` and exposes four deterministic verbs:

- Resolve the encryption root for a dataset.
- List locked descendants under an encryption root.
- Load key material for the encryption root (and descendants).
- Describe keystatus for a dataset list.

```rust
pub trait ZfsProvider {
    type Error;
    fn encryption_root(&self, dataset: &str) -> Result<String, Self::Error>;
    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error>;
    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error>;
    fn describe_datasets(&self, datasets: &[String]) -> Result<KeyStatusSnapshot, Self::Error>;
}
```

### LUKS Provider Contract (`LuksProvider`)

The LUKS provider implements `lockchain_provider::luks::LuksProvider` and focuses on:

- Enumerating manageable crypt mappings (usually sourced from crypttab).
- Unlocking mappings via `cryptsetup` using raw key bytes.
- Reporting mapping state for UI/daemon health.

```rust
pub trait LuksProvider {
    type Error;
    fn list_mappings(&self) -> Result<Vec<LuksMappingDescriptor>, Self::Error>;
    fn unlock_mapping(&self, name: &str, key: &[u8]) -> Result<(), Self::Error>;
    fn mapping_state(&self, name: &str) -> Result<LuksState, Self::Error>;
}
```

Root unlock adds initrd integration (dracut + initramfs-tools) on top of the provider contract; see [`docs/adr/ADR-003-LUKS.md`](adr/ADR-003-LUKS.md).

---

## Providers

### `lockchain-zfs` (Implemented)

- Uses native `zfs`/`zpool` binaries.
- Supports delegated permission mode (`zfs allow load-key,key`) or full-root via polkit/sudo (deployment dependent).
- Designed to keep the contract mockable for tests (`unlock_smoke` uses fake binaries).

### `lockchain-luks` (Scaffolded)

- Scaffolded: provider contract + config plumbing + `cryptsetup` execution wrapper (ADR-003 follow-ups complete the end-to-end unlock path).
- Targets both:
  - **Root unlock** via initrd hooks and crypttab patterns.
  - **Non-root unlock** via systemd units and post-boot workflows.

---

## Capability Matrix (v0.2.x)

Legend: **Yes** (implemented), **Scaffolded** (types/wiring present, workflow not complete), **Planned** (not wired yet).

| Capability | `lockchain-zfs` | `lockchain-luks` |
| --- | --- | --- |
| Provider contracts in `crates/lockchain-provider` | Yes | Yes |
| Unified workflows via `KeyProvider` | Yes (native) | Yes (adapter) |
| USB key normalisation to `/run/lockchain/` | Yes (shared) | Yes (shared) |
| System provider (shell integration) | Yes | Scaffolded |
| Unlock non-root volumes post-boot | Yes | Planned |
| Unlock root volume at early boot | Yes (ZFS initrd) | Planned (ADR-003) |
| dracut loader assets | Yes | Yes |
| initramfs-tools loader assets | Yes | Yes |
| Control Deck UI support | Yes (ZFS mode) | Scaffolded (LUKS mode) |
| Fake-binary provider harness | Yes (`unlock_smoke`) | Planned |

---

## Configuration Files

LockChain uses a unified config file with provider selection:

- Default: `/etc/lockchain.toml`
- Select provider via `[provider] type = "zfs" | "luks" | "auto"` (`kind` is accepted as a legacy alias).
- Configure targets via `[policy] targets = [...]` (ZFS: datasets, LUKS: mapping names; `datasets`, `mappings`, and `volumes` are accepted as legacy aliases).
- Provider-specific sections:
  - ZFS: `[zfs] zfs_path = ...`, `[zfs] zpool_path = ...`
  - LUKS: `[luks] cryptsetup_path = ...`, `[luks] crypttab_path = ...`

When `provider.type = "auto"`, LockChain selects a provider based on configured sections and host tooling presence. Explicit selection is recommended for production/systemd-managed hosts to avoid ambiguity.

Legacy config files are still supported for now (and will be auto-discovered when `/etc/lockchain.toml` is missing):

- ZFS: `/etc/lockchain-zfs.toml` (template: `packaging/providers/zfs/config/lockchain-zfs.toml`)
- LUKS: `/etc/lockchain-luks.toml` (template: `packaging/providers/luks/config/lockchain-luks.toml`)

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
