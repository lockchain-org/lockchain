#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-lockchain-org/lockchain}"

# name;color;description
labels=(
"triage;ededed;Needs grooming"
"type:feature;1f883d;New feature or enhancement"
"type:bug;d73a4a;Bug fix work"
"type:infra;0e8a16;Build/CI/release infra"
"type:test;5319e7;Automated tests or fixtures"
"type:docs;0075ca;Documentation work"
"type:security;b60205;Security-related work"
"priority:essential;b60205;Must-have for alpha"
"priority:high;d93f0b;Important for alpha"
"priority:medium;fbca04;Nice-to-have"
"size:S;c5def5;Small task"
"size:M;bfd4f2;Medium task"
"size:L;c2e0c6;Large task"
)

for entry in "${labels[@]}"; do
  IFS=";" read -r name color desc <<< "$entry"
  if gh label view "$name" --repo "$REPO" >/dev/null 2>&1; then
    gh label edit "$name" --color "$color" --description "$desc" --repo "$REPO"
  else
    gh label create "$name" --color "$color" --description "$desc" --repo "$REPO"
  fi
done

echo "Labels ensured on $REPO"
