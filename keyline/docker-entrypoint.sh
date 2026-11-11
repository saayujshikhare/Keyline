#!/bin/sh
# Mounted volumes (e.g. on Fly.io) arrive owned by root: fix that, then drop privileges.
set -e
if [ -z "$MSGR_PEPPER" ]; then
  echo "MSGR_PEPPER is not set. Generate one with: openssl rand -hex 32" >&2
  exit 1
fi
chown node:node "$DATA_DIR"
exec su-exec node "$@"
