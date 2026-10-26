#!/usr/bin/env sh
# Builds the engine (bin/hi-waf) and the manager (bin/manager).
# Run from anywhere; needs Go 1.26+.
set -eu
cd "$(dirname "$0")/.."
if command -v npm >/dev/null; then (cd console && npm ci --no-audit --no-fund && npm run build); else echo "npm not found: the console will show a \"not built\" page"; fi
go mod tidy
go build -o bin/hi-waf ./cmd/hi-waf
go build -o bin/manager ./cmd/manager
echo "built bin/hi-waf and bin/manager"
