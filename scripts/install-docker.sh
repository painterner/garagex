#!/usr/bin/env bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
. /etc/os-release
case "$ID" in
  ubuntu) ;;
  *) echo "Install Docker Engine and the Compose plugin using your distribution's instructions." >&2; exit 1 ;;
esac
apt-get update
apt-get install -y docker.io docker-compose-v2 python3
systemctl enable --now docker
docker compose version
