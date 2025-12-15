# Architecture Brief

This document explains LockChain’s major components and highlights the system dependencies they rely on.

---

## Guiding Principles

1. **Policy First** — Everything flows from `LockchainConfig`. We load policy once, keep it immutable, and hand it to every surface (CLI, daemon, UI) so the story stays consistent.  
2. **Pluggable Providers** — Provider-native traits live in `crates/lockchain-provider`, and `lockchain-core` consumes a unified `KeyProvider` boundary so the same workflows can target ZFS datasets or LUKS mappings.  
3. **Workflows Everywhere** — Provisioning, unlocking, self-test, and tuning diagnostics all call the same core workflows. Each surface is a different lens on the same machinery.  
4. **Shell At The Edge** — System integrations (`zfs`/`zpool`, `cryptsetup`, initrd hooks) live in provider crates and packaging assets, keeping the steady-state unlock workflows testable and predictable.

## Component Map

| Layer | Responsibility | Architectural note |
| --- | --- | --- |
| **lockchain-provider** | Provider contracts (traits + shared types) | Keeps the workflow engine slim and provider crates decoupled. |
| **lockchain-core** | Policy model, workflow orchestration, error taxonomy | Storage operations stay behind provider contracts; select workflows probe host tooling explicitly (bootstrap/diagnostics/self-test). |
| **lockchain-zfs** | `SystemZfsProvider` implementation | Normalises shell interaction with `zfs`/`zpool`, maps exit codes, parses stdout. |
| **lockchain-luks** | LUKS provider implementation | Scaffolded: `cryptsetup` wrapper + `crypttab` modelling; initrd hooks and end-to-end unlock land via [`docs/adr/ADR-003-LUKS.md`](adr/ADR-003-LUKS.md) follow-ups. |
| **lockchain-daemon** | Long-running supervisor | Applies retry policy, surfaces health, and centralises workflow execution. |
| **lockchain-key-usb** | udev listener & key normaliser | Enforces USB presence, rewrites legacy keys, mirrors material to secure paths. |
| **lockchain-cli / lockchain-ui** | Operator consoles | Provide automation hooks and visual oversight via the same workflow primitives. |

## Data Flow Narrative

1. **Policy Load** — Every binary starts by loading `LockchainConfig` (TOML/YAML). Overrides via env vars keep deployments flexible.  
2. **Provider Selection** — `provider.type` selects `zfs`, `luks`, or `auto`; surfaces resolve the kind and construct the matching system provider at the edge.  
3. **Workflow Selection** — Unlock, forge, recover, self-test, or tuning? Each directive funnels into `lockchain-core::workflow`.  
4. **Provider Boundary** — Unlock/status workflows depend on the unified `KeyProvider` trait, backed by provider-native contracts (`ZfsProvider`, `LuksProvider`).  
5. **Observation & Feedback** — Structured events (`WorkflowReport`) feed the UI activity log, CLI output, and daemon logs. Each carries a severity level and message ready for SOC tooling.

## Provider Plumbing (Unified ZFS/LUKS)

The core unlock service is generic over one provider boundary (`KeyProvider`), so ZFS and LUKS share the same unlock/status orchestration:

- ZFS providers implement `lockchain_provider::zfs::ZfsProvider` and are treated as a `KeyProvider` automatically.  
- LUKS providers implement `lockchain_provider::luks::LuksProvider` and are wrapped in `lockchain_core::provider::LuksKeyProvider` to present `KeyProvider`.  

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

Interpretation: the service layer asks one set of deterministic questions; providers answer in their own substrate (dataset trees vs. mapping state) but the workflows stay the same.

For provider-native trait definitions and the capability matrix, see [`docs/PROVIDERS.md`](PROVIDERS.md).

### Behavioural Guarantees

- Deterministic ordering for target lists — keeps UI tables stable and tests tight.  
- Explicit error mapping — provider failures become `LockchainError::Provider`, config mistakes surface as validation errors.  
- No key custody drift — providers consume raw key bytes and report state; secrets live in configured key paths, not in provider state.

## Shell Boundary

LockChain leans on platform tooling instead of binding to storage libraries. The boundary is intentionally narrow:

- `lockchain-zfs` isolates shell execution (`zfs`/`zpool`) behind a timeout-aware runner and classifies stderr into actionable config vs provider errors.  
- `lockchain-luks` mirrors the same shape for `cryptsetup` (scaffolded today; completed via [`docs/adr/ADR-003-LUKS.md`](adr/ADR-003-LUKS.md) follow-ups).  
- `unlock_smoke` uses fake binaries to keep shell parsing and error mapping testable without requiring real pools.

## Long-running Services

### lockchain-daemon

- Resolves `provider.type`, spins up a `LockchainService<P: KeyProvider>`, and applies the `retry` policy for every configured target.  
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

- **Alternate Providers** — Implement `ZfsProvider`/`LuksProvider` (or `KeyProvider`) for a remote unlock API or a pool-in-container test harness; the CLI and UI won’t notice.  
- **New Workflows** — Compose existing events and the retry machinery to add features (e.g., automated dataset audits).  
- **Telemetry Hooks** — All workflows emit `WorkflowEvent` streams; plug a subscriber in to forward to your observability stack.

## Hand-off Script

For implementation hand-offs:

1. Pair this brief with the configuration schema (`lockchain-cli validate --schema`).  
2. Reference `.github/workflows/release.yml` to show the CI/CD path and packaging guarantees.  
3. Encourage teams to run the Control Deck “Tuning” directive on staging nodes before sign-off.  
4. Highlight the structured log format and `LCxxxx` codes for integration with monitoring systems.

That’s the architecture: modular, observable, and ready for real-world deployments.
