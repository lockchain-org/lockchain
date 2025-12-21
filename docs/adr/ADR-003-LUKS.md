# ADR-003: LUKS Provider + `crypttab` Deployment Patterns

**Status**: Proposed  
**Version target**: v0.2.1+

## Context

LockChain is being rebased as a multi-provider product: the same operator surfaces (CLI/daemon/UI) should orchestrate unlocks for both ZFS encryption roots and LUKS-backed volumes.

ZFS unlocks are already provider-driven and support early-boot integration (dracut + initramfs-tools). We need an equivalent provider crate for LUKS that can unlock:

- **Root devices** (initrd / early-boot path)
- **Non-root devices** (post-boot path via systemd)

## Forces

- **Initrd compatibility** — Support both dracut and initramfs-tools with minimal dependencies in early boot.
- **cryptsetup/crypttab alignment** — Work with the distro’s normal LUKS orchestration (`/etc/crypttab`) instead of inventing a parallel mechanism.
- **Key custody** — Key material stays on the USB token and is only staged into RAM (`/run/cryptsetup-keys.d/` and/or `/run/lockchain`) after checksum + identity enforcement.
- **Operational ergonomics** — Keep patterns legible for platform teams; avoid fragile hacks that drift on updates.

## Decision

1. Introduce `crates/lockchain-luks` as the system provider for LUKS-backed volumes.
2. Define the provider contract in `crates/lockchain-provider` (`lockchain_provider::luks::LuksProvider`).
3. Use `cryptsetup` as the execution substrate and treat `crypttab` as the source of truth for mappings.
4. For root unlock, ship initrd hooks (dracut + initramfs-tools) that:
   - discover and mount the USB token by label/UUID
   - validate key checksum and identity constraints
   - stage key bytes into tmpfs at `/run/cryptsetup-keys.d/<volume-name>.key` with strict perms
   - never write key material to persistent storage (USB-only custody; RAM staging only)

## `crypttab` Patterns

LockChain will support two common deployment lanes.

### 1) Root mapping (initrd)

Use `none` in the key-file field so `cryptsetup`/systemd will automatically look for a key file at:

- `/run/cryptsetup-keys.d/<volume-name>.key` (preferred, tmpfs)
- `/etc/cryptsetup-keys.d/<volume-name>.key` (persistent; not used by LockChain)

Example:

```
cryptroot UUID=<luks-uuid> none luks,discard,initramfs
```

Notes:

- `initramfs` ensures the mapping is handled in early boot where required.
- The `<volume-name>` (first field) must match the LockChain target name under `policy.targets`.
- LockChain stages `/run/cryptsetup-keys.d/cryptroot.key` in initrd (tmpfs, `0400`), and `cryptsetup` consumes it automatically.
- Strict identity enforcement (USB UUID + SHA-256 checksum) happens before any key material is staged.

### 2) Non-root mappings (post-boot)

Non-root mappings can be unlocked by the daemon/CLI and optionally integrated with systemd templates.

Example crypttab entry (post-boot managed):

```
vault UUID=<luks-uuid> none luks,noauto
```

Notes:

- `noauto` prevents boot stalls if the vault stick is absent.
- The `<volume-name>` (first field) must match the LockChain target name under `policy.targets`.
- `lockchain-key-usb` stages `/run/cryptsetup-keys.d/vault.key` while the token is present, so `systemd-cryptsetup@vault.service` can be started on demand.
- `lockchain@.service` (provider selected by config) can also unlock mappings directly via the provider.

## Consequences

**Benefits**

- Brings LUKS under the same provider-driven architecture as ZFS.
- Retains distro-native behaviour for initrd unlock by integrating with crypttab rather than replacing it.
- Keeps key handling consistent across providers: token mounted read-only → checksum/identity checks → keys staged in RAM (`/run/cryptsetup-keys.d`) → unlock workflows.

**Trade-offs**

- Requires careful initrd testing across both dracut and initramfs-tools.
- crypttab differences across distributions must be handled defensively (options, initramfs flags).

## Follow-up Work

- Implement `SystemLuksProvider` in `crates/lockchain-luks` (cryptsetup wrapper + crypttab parsing).
- Add initrd hook assets for both dracut and initramfs-tools (mirroring the existing ZFS loader strategy).
- Add `lockchain-cli luks ...` subcommands and wire the Control Deck context switcher.
- Add tests:
  - crypttab parser fixtures
  - cryptsetup command stubs
  - unit tests for initrd key staging behaviour (no key leakage, strict failures)

— LockChain maintainers
