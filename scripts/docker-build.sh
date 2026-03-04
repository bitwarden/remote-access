#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="bw-proxy"
TAG="latest"
REGISTRY=""
ACR=false
TARGET="x86_64-unknown-linux-musl"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build the bw-proxy Docker image."
    echo ""
    echo "Options:"
    echo "  --name NAME        Image name (default: bw-proxy)"
    echo "  --tag TAG          Image tag (default: latest)"
    echo "  --registry NAME    ACR registry name (e.g. myregistry) for --acr mode"
    echo "  --acr              Build and push to Azure Container Registry"
    echo "  --target TARGET    Cross-compilation target (default: x86_64-unknown-linux-musl)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                     # Cross-compile + build locally"
    echo "  $0 --acr --registry myregistry         # Cross-compile + build in ACR"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --name) IMAGE_NAME="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --registry) REGISTRY="$2"; shift 2 ;;
        --acr) ACR=true; shift ;;
        --target) TARGET="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_DIR="$REPO_ROOT/crates/bw-proxy"
FULL_IMAGE="${IMAGE_NAME}:${TAG}"

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILD_TIME="$(date -u +%Y%m%d-%H%M%S)"
VERSION="${GIT_SHA}-${BUILD_TIME}"

# Phase 1: Cross-compile
echo "Cross-compiling bw-proxy for ${TARGET}..."
cross build --release -p bw-proxy --target "$TARGET"

BINARY="$REPO_ROOT/target/${TARGET}/release/bw-proxy"
if [[ ! -f "$BINARY" ]]; then
    echo "Error: binary not found at $BINARY"
    exit 1
fi

# Phase 2: Assemble minimal Docker context (4 flat files)
CTX="$(mktemp -d)"
trap "rm -rf '$CTX'" EXIT

cp "$BINARY"                        "$CTX/bw-proxy"
cp "$PROXY_DIR/Dockerfile"          "$CTX/Dockerfile"
cp "$PROXY_DIR/Caddyfile"           "$CTX/Caddyfile"
cp "$PROXY_DIR/entrypoint.sh"       "$CTX/entrypoint.sh"

echo "Build context: $(du -sh "$CTX" | cut -f1)"

# Phase 3: Build image
if $ACR; then
    if [[ -z "$REGISTRY" ]]; then
        echo "Error: --registry is required with --acr"
        exit 1
    fi

    echo "Building ${FULL_IMAGE} in ACR (${REGISTRY}.azurecr.io)... [${VERSION}]"
    az acr build \
        --registry "$REGISTRY" \
        --image "$FULL_IMAGE" \
        --platform linux/amd64 \
        --build-arg "VERSION=${VERSION}" \
        "$CTX"
else
    echo "Building ${FULL_IMAGE} locally... [${VERSION}]"
    docker build -t "$FULL_IMAGE" --build-arg "VERSION=${VERSION}" "$CTX"
    echo "Loaded ${FULL_IMAGE} into local Docker"
fi
