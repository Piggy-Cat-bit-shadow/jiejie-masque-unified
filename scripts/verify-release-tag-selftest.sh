#!/usr/bin/env bash
set -euo pipefail

helper=$(git rev-parse --show-toplevel)/scripts/verify-release-tag.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expected=0123456789abcdef0123456789abcdef01234567
fake_gh="$tmp/gh"
cat > "$fake_gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "${1:-}" = api
endpoint=${2:-}
case "${FIXTURE_MODE:-annotated}:$endpoint" in
  annotated:repos/example/repo/git/ref/tags/v1.0.5)
    printf '%s\n' '{"object":{"type":"tag","sha":"abcdef0123456789abcdef0123456789abcdef01"}}' ;;
  annotated:repos/example/repo/git/tags/abcdef0123456789abcdef0123456789abcdef01)
    printf '%s\n' '{"tag":"v1.0.5","object":{"type":"commit","sha":"0123456789abcdef0123456789abcdef01234567"}}' ;;
  lightweight:repos/example/repo/git/ref/tags/v1.0.5)
    printf '%s\n' '{"object":{"type":"commit","sha":"0123456789abcdef0123456789abcdef01234567"}}' ;;
  wrong-target:repos/example/repo/git/ref/tags/v1.0.5)
    printf '%s\n' '{"object":{"type":"tag","sha":"abcdef0123456789abcdef0123456789abcdef01"}}' ;;
  wrong-target:repos/example/repo/git/tags/abcdef0123456789abcdef0123456789abcdef01)
    printf '%s\n' '{"tag":"v1.0.5","object":{"type":"commit","sha":"fedcba9876543210fedcba9876543210fedcba98"}}' ;;
  missing:*)
    exit 1 ;;
  *)
    echo "unexpected fixture request: $endpoint" >&2
    exit 1 ;;
esac
EOF
chmod +x "$fake_gh"

GH_BIN="$fake_gh" FIXTURE_MODE=annotated "$helper" example/repo v1.0.5 "$expected" >/dev/null
if GH_BIN="$fake_gh" FIXTURE_MODE=lightweight "$helper" example/repo v1.0.5 "$expected" >/dev/null 2>&1; then exit 1; fi
if GH_BIN="$fake_gh" FIXTURE_MODE=wrong-target "$helper" example/repo v1.0.5 "$expected" >/dev/null 2>&1; then exit 1; fi
if GH_BIN="$fake_gh" FIXTURE_MODE=annotated "$helper" example/repo v1.0 >/dev/null 2>&1; then exit 1; fi
if GH_BIN="$fake_gh" FIXTURE_MODE=annotated "$helper" example/repo v1.0.5-rc1 "$expected" >/dev/null 2>&1; then exit 1; fi
if GH_BIN="$fake_gh" FIXTURE_MODE=missing "$helper" example/repo v1.0.5 "$expected" >/dev/null 2>&1; then exit 1; fi

# The helper never reads the local tag ref. A synthetic local commit ref does
# not affect the remote annotated fixture and therefore still passes.
git init -q "$tmp/local"
git -C "$tmp/local" config user.email test@example.org
git -C "$tmp/local" config user.name test
git -C "$tmp/local" commit --allow-empty -qm fixture
GH_BIN="$fake_gh" FIXTURE_MODE=annotated "$helper" example/repo v1.0.5 "$expected" >/dev/null
printf '%s\n' 'verify-release-tag-selftest: passed'
