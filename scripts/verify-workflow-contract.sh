#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
workflow=$root/.github/workflows/build.yml
need() { grep -Fqx -- "$1" "$workflow" || { echo "missing workflow contract: $1" >&2; exit 1; }; }

awk '/^  pull_request:/{in_pr=1; next} in_pr && /^  [^ ]/{in_pr=0} in_pr && /^      - /{print}' "$workflow" | grep -Fqx '      - codex/unified-masque' || {
	echo 'pull_request target does not match the repository default branch' >&2
	exit 1
}
need '        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4'
need '        uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5'
need '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4'
need '        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4'
if grep -Eq 'uses: actions/(checkout|setup-go|upload-artifact|download-artifact)@v[0-9]' "$workflow"; then
	echo 'unpinned GitHub Action remains' >&2
	exit 1
fi
printf '%s\n' 'workflow-contract: passed'
