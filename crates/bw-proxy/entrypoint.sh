#!/bin/sh
set -e

cleanup() {
    kill "$BW_PROXY_PID" "$CADDY_PID" 2>/dev/null || true
    wait "$BW_PROXY_PID" "$CADDY_PID" 2>/dev/null || true
}
trap cleanup EXIT TERM INT

bw-proxy &
BW_PROXY_PID=$!

caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!

while kill -0 "$BW_PROXY_PID" 2>/dev/null && kill -0 "$CADDY_PID" 2>/dev/null; do
    sleep 1
done

exit 1
