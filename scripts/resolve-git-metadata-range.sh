#!/usr/bin/env bash
# Resolve the commit range whose identities should be checked by the privacy gate.
# The caller supplies GitHub event values through environment variables.
set -euo pipefail

root=${GIT_METADATA_ROOT:-$(git rev-parse --show-toplevel)}
event=${GIT_METADATA_EVENT:-push}
before=${GIT_METADATA_BEFORE:-}
after=${GIT_METADATA_AFTER:-}
base_sha=${GIT_METADATA_BASE_SHA:-}
default_branch=${GIT_METADATA_DEFAULT_BRANCH:-}
head=${GIT_METADATA_HEAD:-HEAD}
zero=0000000000000000000000000000000000000000

valid_commit() {
	git -C "$root" rev-parse --verify "$1^{commit}" >/dev/null 2>&1
}

head=$(git -C "$root" rev-parse --verify "$head^{commit}")

if [[ $event == pull_request && -n $base_sha ]] && valid_commit "$base_sha"; then
	base=$(git -C "$root" merge-base "$base_sha" "$head")
	printf '%s..%s\n' "$base" "$head"
	exit 0
fi

if [[ $event == push && -n $before && $before != "$zero" && -n $after ]] && \
	valid_commit "$before" && valid_commit "$after"; then
	printf '%s..%s\n' "$before" "$after"
	exit 0
fi

fallback_ref=
if [[ -n $default_branch ]]; then
	if [[ $default_branch == origin/* ]]; then
		fallback_ref=$default_branch
	else
		fallback_ref="origin/$default_branch"
	fi
fi
if [[ -z $fallback_ref ]] || ! valid_commit "$fallback_ref"; then
	fallback_ref=origin/HEAD
fi
if ! valid_commit "$fallback_ref"; then
	echo 'git-metadata: cannot resolve a safe fallback base commit' >&2
	exit 2
fi

base=$(git -C "$root" merge-base "$fallback_ref" "$head")
printf '%s..%s\n' "$base" "$head"
