#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-lockchain-org/lockchain}"

create_issue () {
  local title="$1"
  local body="$2"
  local labels="$3"
  gh issue create --repo "$REPO" --title "$title" --body "$body" --label $labels >/dev/null
  echo "• $title"
}

echo "Creating Essential issues…"
create_issue "Bootstrap repo & CI" \
"Init repo, licenses, CODEOWNERS, PR template; GitHub Actions (lint, test, build).\n\n**AC**: CI green on PR; badge in README." \
"type:infra,priority:essential,size:S"

create_issue "Project architecture & module loader" \
"Define core services, provider interface, DI, config surface.\n\n**AC**: Provider contract documented; mock provider passes tests." \
"type:feature,priority:essential,size:M"

create_issue "CLI MVP: unlock/status/list" \
"Implement \`lockchain unlock\`, \`status\`, \`list-keys\`.\n\n**AC**: Unlock with mocked provider; actionable errors." \
"type:feature,priority:essential,size:M"

create_issue "ZFS provider: system integration" \
"Shell out to \`zpool\`/\`zfs\`; parse output; map exit codes.\n\n**AC**: Unlock works against local test pool; parser unit tests." \
"type:feature,priority:essential,size:M"

create_issue "USB key discovery (udev) & key loader" \
"Detect insertion/removal; load key material from mounted path; handle missing/invalid keys." \
"type:feature,priority:essential,size:M"

create_issue "Config, secrets & logging baseline" \
"YAML/TOML config; secret path env-var; JSON logs; log levels." \
"type:feature,priority:essential,size:S"

create_issue "Unit & smoke tests + fixtures" \
">70% coverage on core; smoke test unlocks a dev pool." \
"type:infra,priority:essential,size:S"

create_issue "Docs: README, CONTRIBUTING, SECURITY, ADR-001" \
"Docs published; ADR captures module/provider approach." \
"type:docs,priority:essential,size:S"

echo "Creating Important issues…"
create_issue "Daemon/service mode" \
"Long-running process watches USB + unlocks target pool; health endpoint/logs." \
"type:feature,priority:high,size:M"

create_issue "systemd units & install scripts" \
"\`lockchain-zfs.service\`/\`lockchain-zfs@.service\`; enables on install; docs." \
"type:infra,priority:high,size:S"

create_issue "Interactive TUI unlock flow" \
"Render pool status, prompt on errors, retry/cancel; keyboard-only." \
"type:feature,priority:high,size:M"

create_issue "Packaging: .deb + signed releases" \
"GitHub Release creates .deb; signature + checksums; tested on Ubuntu 25.10." \
"type:infra,priority:high,size:M"

create_issue "Error taxonomy & retry policy" \
"Consistent codes/messages; exponential backoff parameters configurable." \
"type:feature,priority:high,size:S"

create_issue "Config schema & validator" \
"\`lockchain validate -f <file>\` returns actionable errors." \
"type:feature,priority:high,size:S"

create_issue "Hardening #1: runtime permissions" \
"Runs under dedicated user/group; minimal sudoers entry documented." \
"type:security,priority:high,size:S"

echo "Creating Nice-to-have issues…"
create_issue "Telemetry (opt-in) with sink adapters" \
"Disabled by default; anonymized events; redaction tests." \
"type:feature,priority:medium,size:M"

create_issue "Break-glass recovery command" \
"Document manual steps; explicit confirmations; audit log entry." \
"type:feature,priority:medium,size:S"

create_issue "Performance profiling scripts" \
"Script captures unlock path timings; baseline recorded." \
"type:infra,priority:medium,size:S"

create_issue "Edge-case suite: multi-pool & degraded vdevs" \
"Test matrix covers common failure modes." \
"type:test,priority:medium,size:M"

create_issue "Threat model & attack surface doc" \
"STRIDE table; mitigations mapped to issues." \
"type:security,priority:medium,size:S"

create_issue "Quick Start & Troubleshooting Guide" \
"Copy-paste commands; common errors with fixes." \
"type:docs,priority:medium,size:S"

create_issue "Release notes + changelog automation" \
"Conventional commits -> changelog; first alpha notes generated." \
"type:infra,priority:low,size:S"

echo "✅ All issues created in $REPO"
