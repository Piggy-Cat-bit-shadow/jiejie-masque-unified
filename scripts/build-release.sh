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

output=${OUTPUT:-dist/jiejie-masque-linux-amd64}
mkdir -p "$(dirname "$output")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= -X main.version=$version -X main.commit=$commit" \
  -o "$output" ./cmd/jiejie-masque
bytes=$(stat -c '%s' "$output" 2>/dev/null || stat -f '%z' "$output")
sha=$(sha256sum "$output" | awk '{print $1}')

if [[ "$(go env GOOS)" == linux ]]; then
	expected="jiejie-masque $VERSION commit=$COMMIT"
	actual=$("$output" --version)
	if [[ "$actual" != "$expected" ]]; then
		echo "embedded metadata mismatch: got $actual, want $expected" >&2
		exit 1
	fi
fi

cat > "$(dirname "$output")/RELEASE.txt" <<EOF
name=jiejie-masque
version=$version
commit=$commit
go_version=$(go version | awk '{print $3}')
GOOS=linux
GOARCH=amd64
CGO_ENABLED=0
raw_elf_bytes=$bytes
sha256=$sha
EOF
