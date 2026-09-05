#!/usr/bin/env bash
set -euo pipefail

helper=$(git rev-parse --show-toplevel)/scripts/verify-release-docs.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

write_docs() {
	local readme_marker=$1 maintenance_marker=$2 history=${3:-}
	mkdir -p "$tmp/docs"
	printf '%s\n' "$readme_marker" > "$tmp/README.md"
	printf '%s\n%s\n' "$maintenance_marker" "$history" > "$tmp/docs/maintenance.md"
}

write_docs 'The current maintenance release is `v1.0.12`.' 'Current released version: `v1.0.12`' 'Historical v1.0.11 and v1.0.10 release notes remain valid.'
"$helper" v1.0.12 "$tmp" >/dev/null

write_docs 'The current maintenance release is `v1.0.12`.' $'Current released version: `v1.0.12`\nCurrent released version: `v1.0.11`'
if "$helper" v1.0.12 "$tmp" >/dev/null 2>&1; then exit 1; fi

write_docs 'The current maintenance release is `v1.0.12`.' 'Current released version: `v1.0.12`' 'Historical v1.0.11 release; v1.0.10 final release provenance.'
"$helper" v1.0.12 "$tmp" >/dev/null

write_docs 'The current maintenance release is `v1.0.10`.' 'Current released version: `v1.0.10`'
if "$helper" v1.0.12 "$tmp" >/dev/null 2>&1; then exit 1; fi

write_docs '' 'Current released version: `v1.0.12`'
if "$helper" v1.0.12 "$tmp" >/dev/null 2>&1; then exit 1; fi

printf '%s\n' 'verify-release-docs-selftest: passed'
