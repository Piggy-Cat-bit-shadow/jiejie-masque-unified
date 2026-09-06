#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
git init -q "$root"
git -C "$root" config user.name test

commit() {
  local email=$1 message=$2
  printf '%s\n' "$message" > "$root/file"
  git -C "$root" add file
  GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL="$email" \
    git -C "$root" commit -qm "$message"
}

commit '1+bot@users.noreply.github.com' base
base=$(git -C "$root" rev-parse HEAD)
commit '2+bot@users.noreply.github.com' good
"$(dirname "$0")/verify-git-metadata.sh" "$base..HEAD" "$root"

commit 'private@example.net' bad
if "$(dirname "$0")/verify-git-metadata.sh" "$base..HEAD" "$root"; then
  echo 'non-noreply identity unexpectedly passed' >&2
  exit 1
fi
printf 'git-metadata-selftest: passed\n'
