#!/bin/bash
# Ensure Docker + Compose plugin are installed (same path as install.sh).

set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/library/log.sh"

if [ -f /.dockerenv ]; then
    echo "Inside Docker - dev environment detected. Skipping."
    exit 0
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Docker is installed: $(docker --version)"
    exit 0
fi

echo "Docker not found, installing..."
# Fetched to a file, then run: piped, a dropped download runs half a script.
# get-docker.sh is re-runnable, and its apt steps hit the network too, so the
# run is retried as well as the download.
GET_DOCKER="$(mktemp)"
trap 'rm -f "$GET_DOCKER"' EXIT
retry_net "get.docker.com download" curl -fsSL --max-time 120 https://get.docker.com -o "$GET_DOCKER"
retry_net "get-docker.sh" sh "$GET_DOCKER"
echo "Docker installed: $(docker --version)"
