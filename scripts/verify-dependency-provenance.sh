#!/usr/bin/env bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel)}
docs="$root/docs/maintenance.md"
go_bin=${GO_BIN:-go}

test -f "$docs"
connect_version=$($go_bin -C "$root" list -m -f '{{.Version}}' github.com/Piggy-Cat-bit-shadow/connect-ip-go)
quic_version=$($go_bin -C "$root" list -m -f '{{with .Replace}}{{.Version}}{{end}}' github.com/metacubex/quic-go)

grep -Fqx "current connect-ip-go version: $connect_version" "$docs" || {
  echo "connect-ip-go provenance marker is missing or stale" >&2
  exit 1
}
grep -Fqx "current quic-go replacement version: $quic_version" "$docs" || {
  echo "quic-go provenance marker is missing or stale" >&2
  exit 1
}
printf '%s\n' 'dependency-provenance: passed'
