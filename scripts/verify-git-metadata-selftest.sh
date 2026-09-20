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

resolve_range() {
	GIT_METADATA_ROOT="$root" \
	GIT_METADATA_EVENT="$1" \
	GIT_METADATA_BEFORE="$2" \
	GIT_METADATA_AFTER="$3" \
	GIT_METADATA_BASE_SHA="$4" \
	GIT_METADATA_DEFAULT_BRANCH=main \
	GIT_METADATA_HEAD=HEAD \
	  "$(dirname "$0")/resolve-git-metadata-range.sh"
}

commit '1+bot@users.noreply.github.com' base
base=$(git -C "$root" rev-parse HEAD)
git -C "$root" update-ref refs/remotes/origin/main "$base"

commit 'private@example.net' historical-violation
historical=$(git -C "$root" rev-parse HEAD)
git -C "$root" update-ref refs/remotes/origin/main "$historical"
commit '2+bot@users.noreply.github.com' good
"$(dirname "$0")/verify-git-metadata.sh" "$(resolve_range push "$historical" "$(git -C "$root" rev-parse HEAD)" '' )" "$root"

zero=0000000000000000000000000000000000000000
"$(dirname "$0")/verify-git-metadata.sh" "$(resolve_range push "$zero" "$(git -C "$root" rev-parse HEAD)" '')" "$root"

"$(dirname "$0")/verify-git-metadata.sh" "$(resolve_range pull_request '' '' "$historical")" "$root"

head=$(git -C "$root" rev-parse HEAD)
"$(dirname "$0")/verify-git-metadata.sh" "$head..HEAD" "$root"

commit 'plain@users.noreply.github.com' plain-noreply
"$(dirname "$0")/verify-git-metadata.sh" "$head..HEAD" "$root"

commit 'private@example.net' bad
if "$(dirname "$0")/verify-git-metadata.sh" "$(resolve_range push "$head" "$(git -C "$root" rev-parse HEAD)" '')" "$root"; then
  echo 'non-noreply identity unexpectedly passed' >&2
  exit 1
fi

commit '3+bot@users.noreply.github.com' good-after-bad
commit 'another@example.net' second-bad
if "$(dirname "$0")/verify-git-metadata.sh" "$(resolve_range push "$head" "$(git -C "$root" rev-parse HEAD)" '')" "$root"; then
	echo 'one bad identity in multiple new commits unexpectedly passed' >&2
	exit 1
fi
printf 'git-metadata-selftest: passed\n'
