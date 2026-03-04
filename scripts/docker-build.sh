#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="bw-proxy"
TAG="latest"
REGISTRY=""
ACR=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build the bw-proxy Docker image."
    echo ""
    echo "Options:"
    echo "  --name NAME        Image name (default: bw-proxy)"
    echo "  --tag TAG          Image tag (default: latest)"
    echo "  --registry NAME    ACR registry name (e.g. myregistry) for --acr mode"
    echo "  --acr              Build in Azure Container Registry (linux/amd64)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                     # Build locally (native arch)"
    echo "  $0 --acr --registry myregistry         # Build linux/amd64 in ACR"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --name) IMAGE_NAME="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --registry) REGISTRY="$2"; shift 2 ;;
        --acr) ACR=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_DIR="$REPO_ROOT/crates/bw-proxy"
FULL_IMAGE="${IMAGE_NAME}:${TAG}"

# Assemble a minimal build context in a temp directory.
# The Dockerfile expects a workspace layout (Cargo.toml, Cargo.lock, crates/),
# but we only include the crates bw-proxy actually depends on and trim the
# workspace members list so cargo doesn't look for the others.
assemble_context() {
    local ctx="$1"
    cp "$PROXY_DIR/Dockerfile" "$ctx/"
    cp "$REPO_ROOT/Cargo.lock" "$ctx/"

    # Copy workspace Cargo.toml with only the required members
    awk '
        /^members/ { in_members=1 }
        in_members && /\]/ {
            print "members = ["
            print "    \"crates/bw-error\","
            print "    \"crates/bw-error-macro\","
            print "    \"crates/bw-proxy\","
            print "]"
            in_members=0
            next
        }
        in_members == 0 { print }
    ' "$REPO_ROOT/Cargo.toml" > "$ctx/Cargo.toml"

    # Copy only the crates bw-proxy depends on
    mkdir -p "$ctx/crates"
    for crate in bw-proxy bw-error bw-error-macro; do
        cp -r "$REPO_ROOT/crates/$crate" "$ctx/crates/"
    done

    # Caddy reverse proxy config and entrypoint
    cp "$PROXY_DIR/Caddyfile" "$ctx/crates/bw-proxy/"
    cp "$PROXY_DIR/entrypoint.sh" "$ctx/crates/bw-proxy/"

    # Optional Zscaler CA cert (empty file if not present)
    if [[ -f "$PROXY_DIR/extra-root-ca.crt" ]]; then
        cp "$PROXY_DIR/extra-root-ca.crt" "$ctx/"
    else
        touch "$ctx/extra-root-ca.crt"
    fi

    echo "Build context: $(du -sh "$ctx" | cut -f1)"
}

CTX="$(mktemp -d)"
trap "rm -rf '$CTX'" EXIT
assemble_context "$CTX"

if $ACR; then
    if [[ -z "$REGISTRY" ]]; then
        echo "Error: --registry is required with --acr"
        exit 1
    fi

    echo "Building ${FULL_IMAGE} in ACR (${REGISTRY}.azurecr.io)..."
    az acr build \
        --registry "$REGISTRY" \
        --image "$FULL_IMAGE" \
        --platform linux/amd64 \
        "$CTX"
else
    echo "Building ${FULL_IMAGE} locally..."
    docker build -t "$FULL_IMAGE" "$CTX"
    echo "Loaded ${FULL_IMAGE} into local Docker"
fi
