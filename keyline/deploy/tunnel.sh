#!/usr/bin/env bash
# Runs Keyline on THIS computer and publishes it over HTTPS with a free Cloudflare quick tunnel.
# Needs: Node 22.13+ and cloudflared (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
# Usage:  bash deploy/tunnel.sh      (stop with Ctrl+C)
# The link changes every time you start it, and it works only while this computer is on and online.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cloudflared >/dev/null || { echo "cloudflared is not installed. See the link in this script's comments." >&2; exit 1; }

PORT=8787
# Keyline listens on 127.0.0.1 only, so the tunnel is the only way in. TRUST_PROXY=1 makes rate limits
# see each visitor's real address (forwarded by the tunnel) instead of one shared address for everyone.
HOST=127.0.0.1 PORT=$PORT TRUST_PROXY=1 node --disable-warning=ExperimentalWarning server.js &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT INT TERM
sleep 1
cloudflared tunnel --url "http://127.0.0.1:$PORT"
