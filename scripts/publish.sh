#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/scan_secrets.py --history
git diff --cached --check
if [[ -n $(git status --porcelain) ]]; then
  echo "Commit the reviewed source changes before publishing." >&2
  exit 1
fi
git push origin main
