#!/usr/bin/env bash
# Connect to PostgreSQL with credentials injected via `aac run`.
# Secrets only exist in the child process's environment.
# Usage: ./psql-connect.sh <domain> [psql args...]
set -euo pipefail

domain="$1"; shift
aac run --domain "$domain" --env PGUSER=username --env PGPASSWORD=password -- psql "$@"
