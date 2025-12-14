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
- **Key custody** — Key material is always normalised to `/run/lockchain/key.raw` and validated (checksum + identity enforcement) before use.
- **Operational ergonomics** — Keep patterns legible for platform teams; avoid fragile hacks that drift on updates.

## Decision

1. Introduce `crates/lockchain-luks` as the system provider for LUKS-backed volumes.
2. Define the provider contract in `crates/lockchain-provider` (`lockchain_provider::luks::LuksProvider`).
3. Use `cryptsetup` as the execution substrate and treat `crypttab` as the source of truth for mappings.
4. For root unlock, ship initrd hooks (dracut + initramfs-tools) that:
   - discover and mount the USB token by label/UUID
   - validate key checksum and stage raw bytes into `/run/lockchain/key.raw`
   - expose a `keyscript` entrypoint for `cryptsetup` to read the key material

## `crypttab` Patterns

LockChain will support two common deployment lanes.

### 1) Root mapping (initrd)

Use `keyscript=` so the initrd can fetch the key from LockChain’s staging path.

Example:

```
cryptroot UUID=<luks-uuid> none luks,discard,initramfs,keyscript=/usr/lib/lockchain/lockchain-keyscript
```

Notes:

- `initramfs` ensures the mapping is handled in early boot where required.
- The `lockchain-keyscript` reads from `/run/lockchain/key.raw` (populated by LockChain’s initrd hook), and writes key bytes to stdout for `cryptsetup`.
- Strict identity enforcement (USB UUID + SHA-256 checksum) happens before key material is staged.

### 2) Non-root mappings (post-boot)

Non-root mappings can be unlocked by the daemon/CLI and optionally integrated with systemd templates.

Example crypttab entry (post-boot managed):

```
vault UUID=<luks-uuid> none luks,noauto,keyscript=/usr/lib/lockchain/lockchain-keyscript
```

Notes:

- `noauto` prevents boot stalls if the vault stick is absent.
- `lockchain-luks@.service` (packaging placeholder) is intended to unlock a single mapping on demand.

## Consequences

**Benefits**

- Brings LUKS under the same provider-driven architecture as ZFS.
- Retains distro-native behaviour for initrd unlock by integrating with crypttab rather than replacing it.
- Keeps key handling consistent across providers: USB watcher → `/run/lockchain/key.raw` → provider unlock.

**Trade-offs**

- Requires careful initrd testing across both dracut and initramfs-tools.
- crypttab differences across distributions must be handled defensively (options, keyscript paths, initramfs flags).

## Follow-up Work

- Implement `SystemLuksProvider` in `crates/lockchain-luks` (cryptsetup wrapper + crypttab parsing).
- Add initrd hook assets for both dracut and initramfs-tools (mirroring the existing ZFS loader strategy).
- Add `lockchain-cli luks ...` subcommands and wire the Control Deck context switcher.
- Add tests:
  - crypttab parser fixtures
  - cryptsetup command stubs
  - unit tests for keyscript behaviour (no key leakage, strict failures)

— LockChain maintainers
