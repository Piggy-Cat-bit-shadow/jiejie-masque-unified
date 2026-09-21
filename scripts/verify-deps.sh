#!/usr/bin/env bash
set -euo pipefail
deps=$(mktemp)
trap 'rm -f "$deps"' EXIT
replacement=$(go list -m -f '{{with .Replace}}{{.Path}} {{.Version}}{{end}}' github.com/metacubex/quic-go)
connect_dir=$(go list -m -f '{{.Dir}}' github.com/metacubex/connect-ip-go)
test -n "$connect_dir"
go list -deps ./... >"$deps"
if grep -E '^github.com/quic-go/(quic-go|masque-go)(/|$)' "$deps"; then exit 1; fi
grep -E '^github.com/metacubex/(quic-go|http|tls|connect-ip-go)(/|$)' "$deps"
