#!/usr/bin/env bash
set -euo pipefail

# run_smoke_tests.sh — sets up a venv, installs the library in editable mode, and runs smoke tests.
here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$here"  # assume script is placed at repo root

# venv
if [[ ! -d "$repo_root/.venv" ]]; then
  python3 -m venv "$repo_root/.venv"
fi
# shellcheck disable=SC1091
source "$repo_root/.venv/bin/activate"
pip install -e "$repo_root"

# Prompt for creds if not provided via env (password hidden)
if [[ -z "${FRIGIDAIRE_USERNAME:-}" ]]; then
  read -r -p "Frigidaire username: " FRIGIDAIRE_USERNAME
  export FRIGIDAIRE_USERNAME
fi
if [[ -z "${FRIGIDAIRE_PASSWORD:-}" ]]; then
  read -r -s -p "Frigidaire password: " FRIGIDAIRE_PASSWORD
  echo
  export FRIGIDAIRE_PASSWORD
fi

# Defaults chosen to make spacing visible
MIN_INTERVAL="${MIN_INTERVAL:-1.5}"
JITTER="${JITTER:-0.0}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-15.0}"

python "$repo_root/smoke_test_frigidaire.py" \
  --min-interval "$MIN_INTERVAL" \
  --jitter "$JITTER" \
  --http-timeout "$HTTP_TIMEOUT"
