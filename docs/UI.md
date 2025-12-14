# Control Deck UI

LockChain’s UI (“Control Deck”) is a single operator cockpit that can switch between **ZFS mode** and **LUKS mode** without feeling like two separate applications.

This document captures the intended architecture for that unified UI.

---

## Goals

- **One shell, multiple contexts**: shared navigation, logging, diagnostics, and “directive” actions regardless of provider.
- **Provider-aware views**: datasets and encryption roots for ZFS; crypt mappings and devices for LUKS.
- **No duplicated workflows**: UI triggers the same `lockchain-core` workflows the CLI and daemon use.
- **Operator clarity**: the current provider context is always obvious (labels, status panes, and unit/config hints).

## Proposed Structure (`crates/lockchain-ui`)

### Shared Shell

The top-level app owns:

- global navigation and command palette
- log/event stream rendering
- configuration discovery and validation
- background refresh timers (status + health)

### Provider Contexts

Each provider context owns:

- target list rendering (datasets vs. mappings)
- unlock / status actions for the provider
- provider-specific settings panes (paths, selectors, initrd integration status)

Implementation sketch:

- `enum ProviderContext { Zfs(ZfsContext), Luks(LuksContext) }`
- A small “context adapter” trait for view/update commands so the shell can treat both the same.
- Use provider contracts from `crates/lockchain-provider` for shared types.

## Context Switching

The Control Deck should be able to switch contexts in three ways:

1. **Auto-detect**: prefer `/etc/lockchain.toml`, then fall back to legacy locations (`/etc/lockchain-zfs.toml`, `/etc/lockchain-luks.toml`) and offer valid modes.
2. **Operator toggle**: a quick switcher in the header (keyboard-first).
3. **Explicit launch**: support an override (env var or flag) for automation and screenshots.

Switching contexts must preserve:

- global logs and last actions
- consistent shortcut layout
- consistent severity and `LCxxxx` code presentation

## UI/Workflow Integration

- Unlocking, tuning, repair, and self-test should remain `lockchain-core` workflows.
- Providers are selected by context; the UI does not shell out directly to `zfs` or `cryptsetup`.
- Where possible, the UI should read daemon health (`LOCKCHAIN_HEALTH_ADDR`) and show a local “degraded” banner with actionable next steps.

## Status

As of v0.2.1, ZFS mode is implemented. LUKS mode is scaffolded (provider contract + packaging placeholders) and will be wired in alongside ADR-003 follow-ups.
