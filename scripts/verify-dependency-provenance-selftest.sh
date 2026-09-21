#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/docs"
fake_go="$root/go"
cat > "$fake_go" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *connect-ip-go*) printf '%s\n' 'v0.0.0-20260921032013-13e480e35ff7' ;;
  *metacubex/quic-go*) printf '%s\n' 'v0.61.1-0.20260921031612-beb42da71a55' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_go"

write_docs() {
  cat > "$root/docs/maintenance.md" <<'EOF'
current connect-ip-go version: v0.0.0-20260921032013-13e480e35ff7
current quic-go replacement version: v0.61.1-0.20260921031612-beb42da71a55
historical quic-go SHA: 6d5c3eafe61b
EOF
  cat > "$root/docs/FORKS.md" <<'EOF'
## quic-go
- Pinned commit: `beb42da71a550000000000000000000000000000`

## connect-ip-go
- Pinned commit: `13e480e35ff70000000000000000000000000000`
EOF
}

write_docs
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"

perl -pi -e 's/13e480e35ff7/deadbeef0000/' "$fake_go"
if GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"; then
  echo 'stale provenance marker unexpectedly passed' >&2
  exit 1
fi

perl -pi -e 's/deadbeef0000/13e480e35ff7/' "$fake_go"
write_docs
perl -ni -e 'print unless /historical/' "$root/docs/maintenance.md"
GO_BIN="$fake_go" "$(dirname "$0")/verify-dependency-provenance.sh" "$root"
printf '%s\n' 'dependency-provenance-selftest: passed'
