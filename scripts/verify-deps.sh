#!/usr/bin/env bash
set -euo pipefail
deps=$(mktemp)
trap 'rm -f "$deps"' EXIT
replacement=$(go list -m -f '{{with .Replace}}{{.Path}} {{.Version}}{{end}}' github.com/metacubex/quic-go)
test "$replacement" = 'github.com/Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260920121748-02ac8e5cb125'
go list -deps ./... >"$deps"
if grep -E '^github.com/quic-go/(quic-go|masque-go)(/|$)' "$deps"; then exit 1; fi
grep -E '^github.com/metacubex/(quic-go|http|tls|connect-ip-go)(/|$)' "$deps"
