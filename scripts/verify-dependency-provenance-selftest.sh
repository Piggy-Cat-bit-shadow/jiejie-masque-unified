#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/docs"
fake_go="$root/go"
cat > "$fake_go" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *connect-ip-go*) printf '%s\n' 'v0.0.0-20260921035501-0821cbbd9b16' ;;
  *metacubex/quic-go*) printf '%s\n' 'v0.61.1-0.20260921033957-4587e96afa35' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_go"

write_docs() {
  cat > "$root/docs/maintenance.md" <<'EOF'
current connect-ip-go version: v0.0.0-20260921035501-0821cbbd9b16
current quic-go replacement version: v0.61.1-0.20260921033957-4587e96afa35
historical quic-go SHA: 6d5c3eafe61b
EOF
  cat > "$root/docs/FORKS.md" <<'EOF'
## quic-go
- Pinned commit: `4587e96afa358f7db6f37a71dd92a579ad399e47`

## connect-ip-go
- Pinned commit: `0821cbbd9b16e661044ec62ae930e4659472a36f`
EOF
}

write_docs
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"

perl -pi -e 's/0821cbbd9b16/deadbeef0000/' "$fake_go"
if GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"; then
  echo 'stale provenance marker unexpectedly passed' >&2
  exit 1
fi

perl -pi -e 's/deadbeef0000/0821cbbd9b16/' "$fake_go"
write_docs
perl -ni -e 'print unless /historical/' "$root/docs/maintenance.md"
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"
printf '%s\n' 'dependency-provenance-selftest: passed'
