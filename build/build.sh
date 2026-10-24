#!/usr/bin/env sh
# Builds the engine (bin/hi-waf) and the manager (bin/manager).
# Run from anywhere; needs Go 1.26+.
set -eu
cd "$(dirname "$0")/.."
go mod tidy
go build -o bin/hi-waf ./cmd/hi-waf
go build -o bin/manager ./cmd/manager
echo "built bin/hi-waf and bin/manager"
