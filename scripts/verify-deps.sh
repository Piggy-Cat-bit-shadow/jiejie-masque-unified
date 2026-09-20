#!/usr/bin/env bash
set -euo pipefail
deps=$(mktemp)
trap 'rm -f "$deps"' EXIT
replacement=$(go list -m -f '{{with .Replace}}{{.Path}} {{.Version}}{{end}}' github.com/metacubex/quic-go)
connect_dir=$(go list -m -f '{{.Dir}}' github.com/Piggy-Cat-bit-shadow/connect-ip-go)
connect_replacement=$(awk '$1 == "replace" && $2 == "github.com/metacubex/quic-go" {print $4 " " $5}' "$connect_dir/go.mod")
test "$replacement" = "$connect_replacement"
go list -deps ./... >"$deps"
if grep -E '^github.com/quic-go/(quic-go|masque-go)(/|$)' "$deps"; then exit 1; fi
grep -E '^github.com/metacubex/(quic-go|http|tls|connect-ip-go)(/|$)' "$deps"
