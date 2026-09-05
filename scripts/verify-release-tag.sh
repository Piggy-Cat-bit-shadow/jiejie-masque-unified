#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <owner/repository> <annotated-tag> <expected-commit>" >&2
  exit 2
fi

repository=$1
tag=$2
expected_commit=$3
gh_bin=${GH_BIN:-gh}

[[ "$repository" == */* && -n "${repository%%/*}" && -n "${repository##*/}" ]] || {
  echo "invalid repository: $repository" >&2
  exit 2
}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "invalid release tag: $tag" >&2
  exit 1
}
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid expected commit" >&2
  exit 2
}

ref_json=$($gh_bin api "repos/$repository/git/ref/tags/$tag")
ref_type=$(jq -r '.object.type // empty' <<<"$ref_json")
tag_object_sha=$(jq -r '.object.sha // empty' <<<"$ref_json")
test "$ref_type" = tag || {
  echo "remote release tag is not annotated: $tag" >&2
  exit 1
}
[[ "$tag_object_sha" =~ ^[0-9a-f]{40}$ ]] || {
  echo "remote tag object has invalid SHA" >&2
  exit 1
}

tag_json=$($gh_bin api "repos/$repository/git/tags/$tag_object_sha")
test "$(jq -r '.tag // empty' <<<"$tag_json")" = "$tag" || {
  echo "remote tag object name mismatch: $tag" >&2
  exit 1
}
test "$(jq -r '.object.type // empty' <<<"$tag_json")" = commit || {
  echo "remote tag object does not point to a commit: $tag" >&2
  exit 1
}
target_commit=$(jq -r '.object.sha // empty' <<<"$tag_json")
test "$target_commit" = "$expected_commit" || {
  echo "remote tag target does not match expected commit: $tag" >&2
  exit 1
}

printf 'tag=%s\ntag_object=%s\ntarget_commit=%s\n' \
  "$tag" "$tag_object_sha" "$target_commit"
