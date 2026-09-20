#!/usr/bin/env bash
set -euo pipefail

helper=$(git rev-parse --show-toplevel)/scripts/verify-release-docs.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

write_docs() {
  local readme_marker=$1 maintenance_marker=$2
  mkdir -p "$tmp/docs"
  printf '%s\n' "$readme_marker" > "$tmp/README.md"
  printf '%s\n' "$maintenance_marker" > "$tmp/docs/maintenance.md"
}

write_docs 'The current maintenance release is `v9.9.9`.' 'Current released version: `v9.9.9`'
"$helper" v9.9.9 "$tmp" >/dev/null

write_docs 'The current maintenance release is `v9.9.9`.' $'Current released version: `v9.9.9`\nCurrent released version: `v9.9.8`'
if "$helper" v9.9.9 "$tmp" >/dev/null 2>&1; then exit 1; fi

write_docs 'The current maintenance release is `v9.9.8`.' 'Current released version: `v9.9.9`'
if "$helper" v9.9.9 "$tmp" >/dev/null 2>&1; then exit 1; fi

write_docs '' 'Current released version: `v9.9.9`'
if "$helper" v9.9.9 "$tmp" >/dev/null 2>&1; then exit 1; fi

printf '%s\n' 'verify-release-docs-selftest: passed'
