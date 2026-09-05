#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat >"$tmp/bin/jiejie-masque" <<'EOF'
#!/bin/sh
field=
for arg in "$@"; do
  case "$arg" in
    tunnel-prefix|tunnel-address|tunnel-network|dns-port|external-interface) field=$arg ;;
  esac
done
case "$field" in
  tunnel-prefix) echo 10.200.0.1/16 ;;
  tunnel-address) echo 10.200.0.1 ;;
  tunnel-network) echo 10.200.0.0/16 ;;
  dns-port) [ "${DNS_DISABLED:-0}" = 1 ] || echo 5353 ;;
  external-interface) echo eth0 ;;
esac
EOF
cat >"$tmp/bin/nft" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$tmp/bin/ufw" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$UFW_LOG"
if [ "$1" = status ]; then
  if [ "${UFW_MODE:-active}" = active ]; then
    printf '%s\n' "Status: active"
  else
    printf '%s\n' "Status: inactive"
  fi
elif [ "$1" = show ] && [ "$2" = added ]; then
  if [ "${IDEMPOTENT:-0}" = 1 ]; then
    printf '%s\n' "ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'"
    printf '%s\n' "ufw allow in on masque0 to 10.200.0.1 port 5353 proto tcp comment 'jiejie-masque-connect-ip-dns'"
    printf '%s\n' "ufw route allow in on masque0 out on eth0 from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'"
  else
    printf '%s\n' "ufw allow in on oldtun to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'"
    printf '%s\n' "ufw route allow in on masque0 out on oldeth from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'"
  fi
  printf '%s\n' "ufw allow 22/tcp"
elif [ "${FAIL_ADD:-0}" = 1 ] && [ "$1" = allow ]; then
  exit 1
fi
EOF
chmod +x "$tmp/bin"/*
printf '0\n' >"$tmp/ip_forward"
UFW_LOG="$tmp/ufw.log" \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null

grep -F "allow in on masque0 to 10.200.0.1 port 5353 proto udp" "$tmp/ufw.log"
grep -F "allow in on masque0 to 10.200.0.1 port 5353 proto tcp" "$tmp/ufw.log"
grep -F "route allow in on masque0 out on eth0 from 10.200.0.0/16" "$tmp/ufw.log"
grep -F "delete allow in on oldtun to 10.200.0.1 port 5353 proto udp comment jiejie-masque-connect-ip-dns" "$tmp/ufw.log"
grep -F "delete route allow in on masque0 out on oldeth from 10.200.0.0/16 comment jiejie-masque-connect-ip-forward" "$tmp/ufw.log"
if grep -F "delete allow 22/tcp" "$tmp/ufw.log"; then
  echo 'unrelated UFW rule was deleted' >&2
  exit 1
fi
[ "$(cat "$tmp/ip_forward")" = 1 ]

: >"$tmp/ufw-inactive.log"
printf '1\n' >"$tmp/ip_forward-inactive"
UFW_LOG="$tmp/ufw-inactive.log" UFW_MODE=inactive \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-inactive" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null
if grep -Eq 'allow|delete|show' "$tmp/ufw-inactive.log"; then
  echo 'inactive UFW path changed firewall rules' >&2
  exit 1
fi

printf '1\n' >"$tmp/ip_forward-missing"
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/does-not-exist" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-missing" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null

: >"$tmp/ufw-failure.log"
printf '1\n' >"$tmp/ip_forward-failure"
if UFW_LOG="$tmp/ufw-failure.log" FAIL_ADD=1 \
  JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
  JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
  JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
  JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-failure" \
    "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null; then
  echo 'UFW add failure was not propagated' >&2
  exit 1
fi
if grep -F 'delete ' "$tmp/ufw-failure.log"; then
  echo 'old UFW rules were deleted after add failure' >&2
  exit 1
fi

: >"$tmp/ufw-dns-disabled.log"
printf '1\n' >"$tmp/ip_forward-dns-disabled"
UFW_LOG="$tmp/ufw-dns-disabled.log" DNS_DISABLED=1 \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-dns-disabled" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null
if grep -F 'allow in on masque0 to 10.200.0.1 port 5353' "$tmp/ufw-dns-disabled.log"; then
  echo 'DNS-disabled path added a DNS rule' >&2
  exit 1
fi
grep -F 'delete allow in on oldtun to 10.200.0.1 port 5353 proto udp' "$tmp/ufw-dns-disabled.log"

: >"$tmp/ufw-idempotent.log"
printf '1\n' >"$tmp/ip_forward-idempotent"
UFW_LOG="$tmp/ufw-idempotent.log" IDEMPOTENT=1 \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-idempotent" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null
if grep -Eq 'allow in on masque0|route allow in on masque0' "$tmp/ufw-idempotent.log"; then
  echo 'existing UFW rules were added again' >&2
  exit 1
fi
echo 'connect-ip-network-prepare: active UFW rules passed'
