#!/usr/bin/env bash
set -euo pipefail
deps=$(mktemp)
trap 'rm -f "$deps"' EXIT
go list -deps ./... >"$deps"
if grep -E '^github.com/quic-go/(quic-go|masque-go|qpack)(/|$)' "$deps"; then exit 1; fi
grep -E '^github.com/metacubex/(quic-go|http|tls|connect-ip-go)(/|$)' "$deps"
