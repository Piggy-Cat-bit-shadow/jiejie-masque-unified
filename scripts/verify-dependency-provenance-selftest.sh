#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/docs"
fake_go="$root/go"
cat > "$fake_go" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *connect-ip-go*) printf '%s\n' 'v0.0.0-20260906032034-0bb1cc7fc724' ;;
  *metacubex/quic-go*) printf '%s\n' 'v0.61.1-0.20260906031434-26f04c632d35' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_go"

write_docs() {
  cat > "$root/docs/maintenance.md" <<'EOF'
current connect-ip-go version: v0.0.0-20260906032034-0bb1cc7fc724
current quic-go replacement version: v0.61.1-0.20260906031434-26f04c632d35
historical quic-go SHA: 6d5c3eafe61b
EOF
}

write_docs
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"

perl -pi -e 's/20260906032034/20000101000000/' "$root/docs/maintenance.md"
if GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"; then
  echo 'stale provenance marker unexpectedly passed' >&2
  exit 1
fi

write_docs
perl -ni -e 'print unless /historical/' "$root/docs/maintenance.md"
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"
printf '%s\n' 'dependency-provenance-selftest: passed'
