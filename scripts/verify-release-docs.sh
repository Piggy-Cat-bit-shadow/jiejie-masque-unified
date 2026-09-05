#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 <release-tag> [repository-root]" >&2
	exit 2
fi

tag=$1
root=${2:-$(git rev-parse --show-toplevel)}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
	echo "invalid release tag: $tag" >&2
	exit 2
}

expected_maintenance="The current maintenance release is \`$tag\`."
expected_released="Current released version: \`$tag\`"
files=("$root/README.md" "$root/docs/maintenance.md")

check_marker() {
	local label=$1 pattern=$2 expected=$3 matches value
	matches=$(rg -n -o --no-heading "$pattern" "${files[@]}" || true)
	[[ -n "$matches" ]] || {
		echo "missing current-release marker: $label" >&2
		exit 1
	}
	while IFS= read -r line; do
		value=${line#*:}
		value=${value#*:}
		if [[ "$value" != "$expected" ]]; then
			echo "stale or conflicting current-release marker: $line" >&2
			exit 1
		fi
	done <<< "$matches"
}

check_marker \
	"maintenance" \
	'The current maintenance release is `v[0-9]+\.[0-9]+\.[0-9]+`\.' \
	"$expected_maintenance"
check_marker \
	"released-version" \
	'[Cc]urrent released version:[[:space:]]+`v[0-9]+\.[0-9]+\.[0-9]+`' \
	"$expected_released"

printf 'release-docs: current markers agree on %s\n' "$tag"
