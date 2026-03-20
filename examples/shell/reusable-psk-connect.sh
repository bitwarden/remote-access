#!/usr/bin/env bash
# Connect to a listener using a reusable PSK token and fetch a credential.
# The token is generated once on the listener with `aac listen --reusable-psk`
# and can be reused across runs (e.g., stored as a GitHub Actions secret).
#
# Usage: ./reusable-psk-connect.sh <token> <domain>
#   token   — the 129-char PSK token from the listener
#   domain  — the domain/URI to look up (e.g., "example.com")
#
# Prerequisites:
#   - `aac` binary on PATH
#   - A listener running with `aac listen --reusable-psk` on the proxy
set -euo pipefail

TOKEN="$1"
DOMAIN="$2"

aac connect --token "$TOKEN" --domain "$DOMAIN" --ephemeral-connection --output json
