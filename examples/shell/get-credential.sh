#!/usr/bin/env bash
# Fetch a credential via `aac connect` and pipe it to `docker login`.
# Usage: ./get-credential.sh <domain>
set -euo pipefail

result=$(aac connect --domain "$1" --output json)
username=$(echo "$result" | jq -r '.credential.username')
password=$(echo "$result" | jq -r '.credential.password')

docker login "$1" -u "$username" --password-stdin <<< "$password"
