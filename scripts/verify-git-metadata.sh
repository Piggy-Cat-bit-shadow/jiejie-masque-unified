#!/usr/bin/env bash
# Checks only newly introduced commits. Historical identities are intentionally
# out of scope: pass BASE..HEAD (or another explicit revision range).
set -euo pipefail

range=${1:?usage: verify-git-metadata.sh BASE..HEAD [repository]}
root=${2:-$(git rev-parse --show-toplevel)}
[[ $range == *..* ]] || { echo 'git-metadata: range must be BASE..HEAD' >&2; exit 2; }
git -C "$root" rev-parse --verify "${range%%..*}^{commit}" >/dev/null
git -C "$root" rev-parse --verify "${range##*..}^{commit}" >/dev/null

fail=0
while IFS=$'\t' read -r commit author committer; do
  [[ -z $commit ]] && continue
  for field in "author:$author" "committer:$committer"; do
    identity=${field#*:}
    if [[ ! $identity =~ ^([0-9]+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com$ ]]; then
      printf 'git-metadata: %s commit %s uses non-noreply email %s\n' \
        "${field%%:*}" "$commit" "$identity" >&2
      fail=1
    fi
  done
done < <(git -C "$root" log --format='%H%x09%ae%x09%ce' "$range")

(( fail == 0 )) || exit 1
printf 'git-metadata: newly introduced commit identities are GitHub noreply addresses\n'
