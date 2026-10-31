#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(id -u) != 0 ]]; then echo "Run with sudo for generated container-owned directories." >&2; exit 1; fi
exec python3 scripts/check_isolated.py
