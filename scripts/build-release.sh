#!/usr/bin/env bash
set -euo pipefail

version=${VERSION:-1.0.1}
commit=${COMMIT:-$(git rev-parse --short=12 HEAD)}
output=${OUTPUT:-dist/jiejie-masque-linux-amd64}
mkdir -p "$(dirname "$output")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= -X main.version=$version -X main.commit=$commit" \
  -o "$output" ./cmd/jiejie-masque
bytes=$(stat -c '%s' "$output" 2>/dev/null || stat -f '%z' "$output")
sha=$(sha256sum "$output" | awk '{print $1}')
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
