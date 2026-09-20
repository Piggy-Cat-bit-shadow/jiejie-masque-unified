#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${COMMIT:?COMMIT is required}"

if [[ "$VERSION" != dev && ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "VERSION must be dev or an exact X.Y.Z version" >&2
	exit 2
fi
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
	echo "COMMIT must be a full 40-character lowercase hexadecimal SHA" >&2
	exit 2
fi

version=$VERSION
commit=$COMMIT
connect_version=$(go list -m -f '{{.Version}}' github.com/Piggy-Cat-bit-shadow/connect-ip-go)
quic_version=$(go list -m -f '{{with .Replace}}{{.Version}}{{end}}' github.com/metacubex/quic-go)
pseudo_commit() {
	local module_version=$1
	if [[ "$module_version" =~ -([0-9a-f]{12})$ ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	else
		printf '%s' "$module_version"
	fi
}
connect_module_sha=$(pseudo_commit "$connect_version")
quic_module_sha=$(pseudo_commit "$quic_version")
connect_commit=$(awk -F'`' '/^## connect-ip-go/{fork=1; next} /^## /&&fork{exit} fork&&/Pinned commit:/{print $2; exit}' docs/FORKS.md)
quic_commit=$(awk -F'`' '/^## quic-go/{fork=1; next} /^## /&&fork{exit} fork&&/Pinned commit:/{print $2; exit}' docs/FORKS.md)
test "${connect_commit:0:12}" = "$connect_module_sha"
test "${quic_commit:0:12}" = "$quic_module_sha"

output=${OUTPUT:-dist/jiejie-masque-linux-amd64}
mkdir -p "$(dirname "$output")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= -X main.version=$version -X main.commit=$commit -X main.connectIPGoCommit=$connect_commit -X main.quicGoCommit=$quic_commit" \
  -o "$output" ./cmd/jiejie-masque
bytes=$(stat -c '%s' "$output" 2>/dev/null || stat -f '%z' "$output")
sha=$(sha256sum "$output" | awk '{print $1}')
go_version=$(go version | awk '{print $3}')

if [[ "$(go env GOOS)" == linux ]]; then
	expected="jiejie-masque $VERSION commit=$COMMIT"
	actual=$("$output" --version)
	if [[ "$actual" != "$expected" ]]; then
		echo "embedded metadata mismatch: got $actual, want $expected" >&2
		exit 1
	fi
	verbose=$("$output" --version --verbose)
	grep -Fx "main_commit=$commit" <<<"$verbose" >/dev/null
	grep -Fx "connect_ip_go_commit=$connect_commit" <<<"$verbose" >/dev/null
	grep -Fx "quic_go_commit=$quic_commit" <<<"$verbose" >/dev/null
fi

cat > "$(dirname "$output")/RELEASE.txt" <<EOF
name=jiejie-masque
version=$version
commit=$commit
go_version=$go_version
GOOS=linux
GOARCH=amd64
CGO_ENABLED=0
raw_elf_bytes=$bytes
sha256=$sha
EOF

cat > "$(dirname "$output")/BUILD_PROVENANCE.txt" <<EOF
main_commit=$commit
connect_ip_go_version=$connect_version
connect_ip_go_commit=$connect_commit
quic_go_version=$quic_version
quic_go_commit=$quic_commit
go_version=$go_version
binary_sha256=$sha
EOF
