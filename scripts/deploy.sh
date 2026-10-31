#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(id -u) != 0 ]]; then
  echo "Run with sudo so generated data directories receive the container UIDs." >&2
  exit 1
fi
docker compose version >/dev/null
echo "Listening TCP/UDP ports before deployment:"
ss -lntup
python3 - "$@" <<'PY'
import socket
for port in [80,443]:
    with socket.socket() as sock:
        try: sock.bind(("0.0.0.0",port))
        except OSError: raise SystemExit(f"Port {port} is occupied. Existing services were not changed.")
PY
python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    try:sock.bind(("0.0.0.0",443))
    except OSError:raise SystemExit("UDP port 443 is occupied. Existing services were not changed.")
PY
python3 scripts/configure.py "$@"
docker compose up -d --build
echo "Deployment started. Inspect: sudo docker compose logs --tail=50"
echo "Read credentials locally: sudo cat .runtime/secrets/credentials.json"
