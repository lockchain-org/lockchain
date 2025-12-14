#!/usr/bin/env bash
set -euo pipefail

# Profile the unlock workflow and record timing/baseline entries without
# reimplementing the application's logging stack.

usage() {
  cat <<'EOF'
Usage: profile-unlock.sh [--config PATH] [--dataset DATASET] [--strict-usb] [--note TEXT] [--passphrase TEXT] [--prompt-passphrase] [--key-file PATH]

Runs `lockchain-cli profile-unlock` and leaves a timing entry in the shared
performance log (see LOCKCHAIN_LOG_ROOT). The first successful run per dataset
captures the baseline automatically.
EOF
}

CONFIG="${LOCKCHAIN_CONFIG:-/etc/lockchain.toml}"
DATASET=""
NOTE=""
STRICT=false
PASSPHRASE=""
PROMPT=false
KEY_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --dataset)
      DATASET="$2"
      shift 2
      ;;
    --note)
      NOTE="$2"
      shift 2
      ;;
    --strict-usb)
      STRICT=true
      shift 1
      ;;
    --passphrase)
      PASSPHRASE="$2"
      shift 2
      ;;
    --prompt-passphrase)
      PROMPT=true
      shift 1
      ;;
    --key-file)
      KEY_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$DATASET" ]]; then
        DATASET="$1"
      else
        echo "Unknown argument: $1" >&2
        usage
        exit 1
      fi
      shift 1
      ;;
  esac
done

if ! command -v lockchain-cli >/dev/null 2>&1; then
  echo "lockchain-cli not found on PATH" >&2
  exit 1
fi

cmd=(lockchain-cli --config "$CONFIG" profile-unlock)
[[ -n "$DATASET" ]] && cmd+=("$DATASET")
$STRICT && cmd+=(--strict-usb)
[[ -n "$NOTE" ]] && cmd+=(--note "$NOTE")
[[ -n "$PASSPHRASE" ]] && cmd+=(--passphrase "$PASSPHRASE")
$PROMPT && cmd+=(--prompt-passphrase)
[[ -n "$KEY_FILE" ]] && cmd+=(--key-file "$KEY_FILE")

echo "Profiling unlock path with: ${cmd[*]}"
"${cmd[@]}"
