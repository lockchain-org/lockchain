# Threat Model & IEC 62443 Mapping

This brief captures the current attack surface for LockChain’s **ZFS provider** and maps the implemented controls to the IEC 62443-3-3 foundational requirements so implementers can gauge fit before deployment.

---

## Scope & Assets

- **Assets:** ZFS raw keys on removable media, `lockchain` configuration, initramfs loader artifacts, structured logs, and ZFS datasets marked for headless unlock.
- **Surfaces:** USB token provisioning path, initramfs loader (`lockchain-load-key`), systemd units and drop-ins, `lockchain-key-usb` watcher, CLI/UI workflows, and ZFS provider shell calls.
- **Trust boundaries:** Transition into initramfs (pre-root), hand-off from udev to `lockchain-key-usb`, and privilege elevation via `pkexec`/`sudo` when required.
- **Assumptions:** Kernel and ZFS modules are trusted; host clock reasonably accurate; operator controls physical access to removable media; journald available or equivalent logging sink configured.

## Threat Posture

- **Key substitution / tamper:** Mitigated by raw 32-byte keys, enforced `0400` permissions, SHA-256 checksums in policy, UUID+label binding, and read-only mounts in initramfs.
- **Loader bypass:** Dracut/initramfs-tools modules set `keylocation=file://…` and run before `zfs-load-key`; tuning verifies assets and rebuilds images to avoid drift.
- **Stale or poisoned media:** `lockchain-key-usb` normalises keys, refuses unexpected sizes, and clears destination keys on failure; provisioning wipes and re-labels media unless in safe mode.
- **Replay of legacy hex keys:** Hex material is auto-converted to raw and rewritten; tuning repairs policy checksum when missing.
- **Log privacy:** JSON logs default; `lockchain` user runs services; file custody (`/etc/lockchain.toml` 640, keys 400) limits leakage.

## IEC 62443-3-3 Foundational Requirements Mapping

| SR | Requirement | LockChain controls | Coverage | Notes / residual risk |
| --- | --- | --- | --- | --- |
| SR 1 – Identification & Authentication Control | Authenticate principals and assets | Systemd units run as dedicated `lockchain`; policy file ownership; pkexec escalation prompts; UUID/label binding for tokens | Partial | Does not ship its own authN; relies on host account controls and udev rules. |
| SR 2 – Use Control | Enforce authorised use | Sudoers guidance, `run_external` privilege wrapper, read-only mounts in initramfs, key permissions enforced to 0400 | Partial | Operator must apply sudoers/ACLs; no built-in RBAC beyond host OS. |
| SR 3 – System Integrity | Protect against unauthorised modification | Initramfs assets regenerated with checksums, audit via `lsinitrd/lsinitramfs`, key checksum verification, hex→raw normalisation, safe-mode provisioning | Partial | Integrity of host binaries assumed; no secure boot attestation performed. |
| SR 4 – Data Confidentiality | Prevent disclosure of sensitive data | Raw keys only, 32-byte size enforcement, tmpfs staging (`/run/lockchain`), zeroisation in memory (Zeroizing), checksum validation before use | Partial | Keys at rest on removable media remain sensitive; rely on physical controls or crypto-on-token if required. |
| SR 5 – Restricted Data Flow | Enforce least data paths | Keylocation fixed to token path, read-only mounts in initramfs, avoids copying keys to writable `/run` in early boot | Partial | Network segmentation not in scope; applies only to key handling paths. |
| SR 6 – Timely Response to Events | Detect and react | Structured events in workflows, journald sampling in Tuning/Doctor, loader exits cleanly to native prompts on failure | Partial | No active alerting; operator must forward logs to SIEM and set policies. |
| SR 7 – Resource Availability | Sustain required operation | Read-only mount retries, remount-rw fallback during provisioning, self-test workflow, graceful fallback to passphrase prompts | Partial | No DoS hardening beyond retries; availability depends on underlying storage and boot stack. |

## Coverage Notes

- **Met by design:** Key format enforcement, checksum binding, initramfs asset auditing and rebuild, loader ordering ahead of `zfs-load-key`, safe read-only handling in early boot.
- **Operator actions required:** Apply sudoers policy, secure physical media, forward logs/alerts, and keep OS/ZFS patched. Consider full-disk encryption for removable media if mandated.
- **Out of scope:** Network segmentation, host secure-boot attestation, and hardware-backed key storage.
