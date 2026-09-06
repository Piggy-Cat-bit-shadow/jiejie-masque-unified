#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
workflow=$root/.github/workflows/build.yml
need() { grep -Fqx -- "$1" "$workflow" || { echo "missing workflow contract: $1" >&2; exit 1; }; }

awk '/^  pull_request:/{in_pr=1; next} in_pr && /^  [^ ]/{in_pr=0} in_pr && /^      - /{print}' "$workflow" | grep -Fqx '      - codex/unified-masque' || {
	echo 'pull_request target does not match the repository default branch' >&2
	exit 1
}
need '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
need '        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0'
need '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
need '        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1'
release_deps_count=$(grep -c -F '      - name: Install release verifier dependencies' "$workflow" || true)
release_deps_line_1=$(grep -n -F '      - name: Install release verifier dependencies' "$workflow" | sed -n '1p' | cut -d: -f1)
release_deps_line_2=$(grep -n -F '      - name: Install release verifier dependencies' "$workflow" | sed -n '2p' | cut -d: -f1)
metadata_line=$(grep -n -F '      - name: Resolve build metadata' "$workflow" | cut -d: -f1)
release_validate_line=$(grep -n -F '      - name: Validate tag and release notes' "$workflow" | cut -d: -f1)
if [[ "$release_deps_count" -ne 2 || -z "$metadata_line" || -z "$release_validate_line" || -z "$release_deps_line_1" || -z "$release_deps_line_2" || "$release_deps_line_1" -ge "$metadata_line" || "$release_deps_line_2" -ge "$release_validate_line" ]]; then
	echo 'release verifier dependencies must be installed before build metadata resolution' >&2
	exit 1
fi
for release_deps_line in "$release_deps_line_1" "$release_deps_line_2"; do
  grep -Fqx -- '        run: sudo apt-get update && sudo apt-get install -y ripgrep' <(sed -n "${release_deps_line},$((release_deps_line + 1))p" "$workflow") || {
	echo 'release verifier dependency installation is not ripgrep-based' >&2
	exit 1
  }
done
if grep -Eq 'uses: actions/(checkout|setup-go|upload-artifact|download-artifact)@v[0-9]' "$workflow"; then
	echo 'unpinned GitHub Action remains' >&2
	exit 1
fi
printf '%s\n' 'workflow-contract: passed'
