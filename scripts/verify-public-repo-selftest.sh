#!/usr/bin/env bash
set -euo pipefail

scanner=$(git rev-parse --show-toplevel)/scripts/verify-public-repo.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" config user.email test@example.org
git -C "$tmp" config user.name test
printf 'listen: 127.0.0.1:4433\n' > "$tmp/README.md"
git -C "$tmp" add README.md && git -C "$tmp" commit -qm fixture

bin="$tmp/bin"
mkdir "$bin"
ln -s "$(command -v git)" "$bin/git"
if (cd "$tmp" && PATH="$bin" /bin/bash "$scanner") 2>/dev/null; then
  echo 'selftest: missing rg was not rejected' >&2
  exit 1
fi

check_rejected() {
  printf '%s\n' "$2" > "$tmp/README.md"
  git -C "$tmp" add README.md && git -C "$tmp" commit -qm fixture
  if (cd "$tmp" && bash "$scanner") >/dev/null 2>&1; then
    echo "selftest: scanner accepted $1" >&2
    exit 1
  fi
}
check_rejected private-key '-----BEGIN PRIVATE KEY-----'
check_rejected public-ip 'target: 8.8.8.8'
printf '%s\n' 'listen: 127.0.0.1:4433' 'network: 10.0.0.0/8' 'reference: example.com' > "$tmp/README.md"
git -C "$tmp" add README.md && git -C "$tmp" commit -qm allowed
(cd "$tmp" && bash "$scanner")
echo 'public-repo-selftest: passed'
