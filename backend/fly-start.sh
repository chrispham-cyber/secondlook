#!/bin/sh
set -e

mkdir -p /data /var/run/tailscale /var/lib/tailscale
chown appuser /data

if [ -n "$TS_AUTHKEY" ]; then
  # In-memory state plus an ephemeral key: every restart joins as a fresh node, and old ones
  # are removed automatically.
  tailscaled --state=mem: --socket=/var/run/tailscale/tailscaled.sock &
  tailscale --socket=/var/run/tailscale/tailscaled.sock up \
    --auth-key="$TS_AUTHKEY" --hostname="${TS_HOSTNAME:-secondlook-fly}" --accept-dns=false --timeout=30s \
    || echo "Tailscale didn't connect. Scans will run without the AI."
else
  echo "TS_AUTHKEY not set. Scans will run without the AI."
fi
unset TS_AUTHKEY

export HOME=/home/appuser
exec setpriv --reuid=appuser --regid=appuser --init-groups \
  uv run --no-sync uvicorn app.main:app --host :: --port "${PORT:-8000}"
