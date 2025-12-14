# Architecture Brief

This document explains LockChain’s major components and highlights the system dependencies they rely on.

---

## Guiding Principles

1. **Policy First** — Everything flows from `LockchainConfig`. We load policy once, keep it immutable, and hand it to every surface (CLI, daemon, UI) so the story stays consistent.  
2. **Pluggable Providers** — Provider traits live in `crates/lockchain-provider`. Today we shell out to `zfs`/`zpool`; tomorrow we can point at an RPC bridge (or a LUKS provider) without rewriting business logic.  
3. **Workflows Everywhere** — Provisioning, unlocking, self-test, and tuning diagnostics all call the same core workflows. Each surface is a different lens on the same machinery.

## Component Map

| Layer | Responsibility | Architectural note |
| --- | --- | --- |
| **lockchain-provider** | Provider contracts (traits + shared types) | Keeps the workflow engine slim and provider crates decoupled. |
| **lockchain-core** | Policy model, workflow orchestration, error taxonomy | Pure Rust, no direct system calls, designed for deterministic tests. |
| **lockchain-zfs** | `SystemZfsProvider` implementation | Normalises shell interaction with `zfs`/`zpool`, maps exit codes, parses stdout. |
| **lockchain-luks** | LUKS provider implementation | Planned: wraps `cryptsetup`, models `crypttab`, ships initrd hooks (ADR-003). |
| **lockchain-daemon** | Long-running supervisor | Applies retry policy, surfaces health, and centralises workflow execution. |
| **lockchain-key-usb** | udev listener & key normaliser | Enforces USB presence, rewrites legacy keys, mirrors material to secure paths. |
| **lockchain-cli / lockchain-ui** | Operator consoles | Provide automation hooks and visual oversight via the same workflow primitives. |

## Data Flow Narrative

1. **Policy Load** — Every binary starts by loading `LockchainConfig` (TOML/YAML). Overrides via env vars keep deployments flexible.  
2. **Workflow Selection** — Unlock, forge, recover, self-test, or tuning? Each directive funnels into `lockchain-core::workflow`.  
3. **Provider Boundary** — Workflows depend on provider contracts from `lockchain-provider` (today: `ZfsProvider`; next: `LuksProvider`).  
4. **Observation & Feedback** — Structured events (`WorkflowReport`) feed the UI activity log, CLI output, and daemon logs. Each carries a severity level and message ready for SOC tooling.

### The ZFS Provider Contract

```rust
pub trait ZfsProvider {
    type Error;
    fn encryption_root(&self, dataset: &str) -> Result<String, Self::Error>;
    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error>;
    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error>;
    fn describe_datasets(&self, datasets: &[String]) -> Result<KeyStatusSnapshot, Self::Error>;
}
```

Interpretation: the service layer asks ZFS four deterministic questions; providers respond consistently and capture enough context for audit.

### Behavioural Guarantees

- Deterministic ordering for dataset lists — keeps UI tables stable and tests tight.  
- Explicit error mapping — provider failures become `LockchainError::Provider`, config mistakes surface as validation errors.  
- Zero direct config reads inside providers — keeps the contract pure and drop-in replacements painless.

## Long-running Services

### lockchain-daemon

- Spins up a `LockchainService<SystemZfsProvider>` and applies the `retry` policy for every dataset.  
- Exposes `GET /` on `LOCKCHAIN_HEALTH_ADDR` returning `OK` or `DEGRADED` with human-readable reasons.  
- Emits `[LC2xxx]` codes on successful unlocks, `[LC5xxx]` when providers misbehave, perfect for alert routing.

### lockchain-key-usb

- Watches udev for USB partitions, filters by label/UUID, mounts read-only when possible.  
- Reads key material, normalises hex → raw, writes to the configured path with `0400` permissions, and updates the checksum if policy expects it.  
- Clears the destination if checks fail to avoid stale or poisoned keys.

The daemon and watcher share config and logging, so you get one cohesive story in the logs.

## Workflow Spotlight

| Workflow | What it does | Architectural impact |
| --- | --- | --- |
| **New Key** (`workflow::forge_key`) | Prepares the USB device, writes raw key material, refreshes initramfs assets, updates policy. | Establishes the baseline state; ensures downstream tooling sees fully hardened media. |
| **Self-test** (`workflow::self_test`) | Creates an ephemeral pool, validates unlock, confirms keystatus, tears everything down. | Proof that current key material remains functional without touching production pools. |
| **Tuning** (`workflow::tune`) | Inspects journald, reviews systemd units, verifies dracut/initramfs tooling, reapplies system integration defaults. | Provides readiness data you can hand to operations or compliance. |
| **Recover** (`workflow::recover_key`) | Derives fallback key material, writes it with `0400`, emits security events. | Binds emergency recovery to policy and audit signals. |

## Extension Points

- **Alternate Providers** — Implement `ZfsProvider` for a remote unlock API or pool-in-container testing; the CLI and UI won’t notice.  
- **New Workflows** — Compose existing events and the retry machinery to add features (e.g., automated dataset audits).  
- **Telemetry Hooks** — All workflows emit `WorkflowEvent` streams; plug a subscriber in to forward to your observability stack.

## Hand-off Script

For implementation hand-offs:

1. Pair this brief with the configuration schema (`lockchain-cli validate --schema`).  
2. Reference `.github/workflows/release.yml` to show the CI/CD path and packaging guarantees.  
3. Encourage teams to run the Control Deck “Tuning” directive on staging nodes before sign-off.  
4. Highlight the structured log format and `LCxxxx` codes for integration with monitoring systems.

That’s the architecture: modular, observable, and ready for real-world deployments.
