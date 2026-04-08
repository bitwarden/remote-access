#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --out-dir pkg
echo ""
echo "Build complete! To run the demo:"
echo "  npm install && npm run dev"
