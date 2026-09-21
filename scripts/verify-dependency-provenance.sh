#!/usr/bin/env bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel)}
go_bin=${GO_BIN:-go}

connect_version=$($go_bin -C "$root" list -m -f '{{with .Replace}}{{.Version}}{{end}}' github.com/metacubex/connect-ip-go)
quic_version=$($go_bin -C "$root" list -m -f '{{with .Replace}}{{.Version}}{{end}}' github.com/metacubex/quic-go)
[[ "$connect_version" == *-0821cbbd9b16 ]] || { echo "connect-ip-go pin is stale: $connect_version" >&2; exit 1; }
[[ "$quic_version" == *-4587e96afa35 ]] || { echo "quic-go replacement pin is stale: $quic_version" >&2; exit 1; }
printf '%s\n' 'dependency-provenance: passed'
