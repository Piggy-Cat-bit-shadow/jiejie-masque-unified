#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/docs"
fake_go="$root/go"
cat > "$fake_go" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *connect-ip-go*) printf '%s\n' 'v0.0.0-20260906025925-bc8c4a81f79f' ;;
  *metacubex/quic-go*) printf '%s\n' 'v0.61.1-0.20260906020448-5dd41cf92b47' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_go"

write_docs() {
  cat > "$root/docs/maintenance.md" <<'EOF'
current connect-ip-go version: v0.0.0-20260906025925-bc8c4a81f79f
current quic-go replacement version: v0.61.1-0.20260906020448-5dd41cf92b47
historical quic-go SHA: 6d5c3eafe61b
EOF
}

write_docs
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"

perl -pi -e 's/20260906025925/20000101000000/' "$root/docs/maintenance.md"
if GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"; then
  echo 'stale provenance marker unexpectedly passed' >&2
  exit 1
fi

write_docs
perl -ni -e 'print unless /historical/' "$root/docs/maintenance.md"
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"
printf '%s\n' 'dependency-provenance-selftest: passed'
