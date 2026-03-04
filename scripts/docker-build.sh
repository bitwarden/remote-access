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
FULL_IMAGE="${IMAGE_NAME}:${TAG}"

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
        "$REPO_ROOT"
else
    echo "Building ${FULL_IMAGE} locally..."
    docker build -t "$FULL_IMAGE" "$REPO_ROOT"
    echo "Loaded ${FULL_IMAGE} into local Docker"
fi
