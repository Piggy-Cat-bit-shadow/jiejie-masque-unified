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
  local path=$1
  local content=$2
  mkdir -p "$tmp/$(dirname "$path")"
  printf '%s\n' "$content" > "$tmp/$path"
  git -C "$tmp" add -A && git -C "$tmp" commit -qm "reject $path"
  if (cd "$tmp" && bash "$scanner") >/dev/null 2>&1; then
    echo "selftest: scanner accepted $path" >&2
    exit 1
  fi
}

# Keep the marker split so the scanner does not match this fixture source in
# the real repository when it performs its repo-wide scan.
pem_fixture='-----BEGIN '"PRIVATE KEY-----"
sec1_fixture="MHcCAQEEI$(printf 'A%.0s' {1..80})"
pkcs8_fixture="MIGHAgEAMBMGByqGSM49$(printf 'A%.0s' {1..40})"
check_rejected internal/leak.txt "$pem_fixture"
check_rejected docs/leak.md "$sec1_fixture"
check_rejected .github/leak.yml "secret: $pkcs8_fixture"
check_rejected README.md 'target: 8.8.8.8'

rm -rf "$tmp/internal" "$tmp/docs" "$tmp/.github"
printf '%s\n' 'listen: 127.0.0.1:4433' 'network: 10.0.0.0/8' 'reference: example.com' > "$tmp/README.md"
git -C "$tmp" add -A && git -C "$tmp" commit -qm allowed
(cd "$tmp" && bash "$scanner")

# A synthetic public PKIX key prefix is not a private-key match.
mkdir -p "$tmp/.github"
printf '%s\n' 'public-key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc=' > "$tmp/.github/public.yml"
git -C "$tmp" add -A && git -C "$tmp" commit -qm public-key
(cd "$tmp" && bash "$scanner")
echo 'public-repo-selftest: passed'
