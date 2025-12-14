#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash scripts/create-project.sh "Lockchain ZFS Alpha" YOUR_GH_USERNAME OWNER/REPO
#
# Requires: gh (recent) and jq

PROJECT_NAME="${1:-Lockchain ZFS Alpha}"
OWNER="${2:-@me}"
REPO="${3:-OWNER/REPO}"

need() { command -v "$1" >/dev/null || { echo "❌ Missing $1"; exit 1; }; }
need gh
need jq

gh auth status >/dev/null 2>&1 || { echo "❌ Not logged in. Run: gh auth login"; exit 1; }

# --- 1) Create a fresh user project (simplest, most reliable) ---
project_num="$(gh project create --owner "$OWNER" --title "$PROJECT_NAME" --format json | jq -r '.number')"
echo "✅ Created project #$project_num"

# Get GraphQL node id (needed for item field edits)
project_node_id="$(gh project view "$project_num" --owner "$OWNER" --format json | jq -r '.id')"

# --- 2) Create fields (skip STATUS, it's built-in) ---
ensure_field () {
  local name="$1"; local dtype="$2"; local options="${3:-}"
  set +e
  if [[ -n "$options" ]]; then
    gh project field-create "$project_num" --owner "$OWNER" --name "$name" --data-type "$dtype" --single-select-options "$options" >/dev/null 2>&1
  else
    gh project field-create "$project_num" --owner "$OWNER" --name "$name" --data-type "$dtype" >/dev/null 2>&1
  fi
  set -e
  echo "• Ensured field: $name ($dtype)"
}

ensure_field "Priority" "SINGLE_SELECT" "essential,high,medium,low"
ensure_field "Size"     "SINGLE_SELECT" "S,M,L"
ensure_field "Sprint"   "TEXT"
ensure_field "Target Release" "TEXT"

# Helper to read field id by name across both possible JSON shapes
get_field_id () {
  local fname="$1"
  local raw="$(gh project field-list "$project_num" --owner "$OWNER" --format json)"
  # If it looks like {"fields":[...]}, use .fields[]; else assume it's just an array []
  if echo "$raw" | jq -e '.fields' >/dev/null 2>&1; then
    echo "$raw" | jq -r --arg n "$fname" '.fields[] | select(.name==$n) | .id' | head -n1
  else
    echo "$raw" | jq -r --arg n "$fname" '.[]       | select(.name==$n) | .id' | head -n1
  fi
}

sprint_field_id="$(get_field_id "Sprint")"
if [[ -z "$sprint_field_id" || "$sprint_field_id" == "null" ]]; then
  echo "❌ Could not find Sprint field id"; exit 1
fi

# --- 3) Link repo and add all open issues as project items ---
gh project link "$project_num" --owner "$OWNER" --repo "$REPO" >/dev/null 2>&1 || true

echo "Adding open issues from $REPO to project…"
issue_urls="$(gh issue list --repo "$REPO" --state open --json url | jq -r '.[].url' || true)"
if [[ -n "$issue_urls" ]]; then
  while read -r url; do
    [[ -z "$url" ]] && continue
    gh project item-add "$project_num" --owner "$OWNER" --url "$url" >/dev/null
  done <<< "$issue_urls"
  echo "✅ Issues added to project"
else
  echo "ℹ️ No open issues found in $REPO (run scripts/create-issues.sh first)."
fi

# --- 4) Auto-set Sprint field (Week 1/2/3) by issue title ---
declare -A SPRINT_BY_TITLE=(
  # Week 1
  ["Bootstrap repo & CI"]="Week 1"
  ["Project architecture & module loader"]="Week 1"
  ["CLI MVP: unlock/status/list"]="Week 1"
  ["ZFS provider: system integration"]="Week 1"
  ["USB key discovery (udev) & key loader"]="Week 1"
  ["Config, secrets & logging baseline"]="Week 1"
  ["Unit & smoke tests + fixtures"]="Week 1"
  ["Docs: README, CONTRIBUTING, SECURITY, ADR-001"]="Week 1"
  # Week 2
  ["Daemon/service mode"]="Week 2"
  ["systemd units & install scripts"]="Week 2"
  ["Interactive TUI unlock flow"]="Week 2"
  ["Packaging: .deb + signed releases"]="Week 2"
  ["Error taxonomy & retry policy"]="Week 2"
  ["Config schema & validator"]="Week 2"
  ["Hardening #1: runtime permissions"]="Week 2"
  # Week 3
  ["Telemetry (opt-in) with sink adapters"]="Week 3"
  ["Break-glass recovery command"]="Week 3"
  ["Performance profiling scripts"]="Week 3"
  ["Edge-case suite: multi-pool & degraded vdevs"]="Week 3"
  ["Threat model & attack surface doc"]="Week 3"
  ["Quick Start & Troubleshooting Guide"]="Week 3"
  ["Release notes + changelog automation"]="Week 3"
)

# Pull items; tolerate both shapes again
items_json="$(gh project item-list "$project_num" --owner "$OWNER" --format json)"
# Normalize to one-item-per-line
if echo "$items_json" | jq -e 'type=="array"' >/dev/null 2>&1; then
  mapfile -t items < <(echo "$items_json" | jq -c '.[]')
else
  # unexpected shape, try to find an array inside
  mapfile -t items < <(echo "$items_json" | jq -c '.. | arrays? // empty | .[]')
fi

echo "Setting Sprint field values…"
setcnt=0
for item in "${items[@]}"; do
  item_id="$(jq -r '.id' <<<"$item")"
  title="$(jq -r '.content.title // empty' <<<"$item")"
  [[ -z "$item_id" || -z "$title" ]] && continue
  if [[ -n "${SPRINT_BY_TITLE[$title]+_}" ]]; then
    sprint_val="${SPRINT_BY_TITLE[$title]}"
    # Use item-edit to set TEXT field
    gh project item-edit \
      --id "$item_id" \
      --project-id "$project_node_id" \
      --field-id "$sprint_field_id" \
      --text "$sprint_val" >/dev/null
    echo "• $title → $sprint_val"
    setcnt=$((setcnt+1))
  fi
done
echo "✅ Sprint values set for $setcnt item(s)."

echo
echo "Open the project:"
echo "  gh project view $project_num --owner $OWNER --web"

