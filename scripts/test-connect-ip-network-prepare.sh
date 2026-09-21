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
    tunnel-prefix|tunnel-ipv4-prefix|tunnel-ipv6-prefix|tunnel-ipv4-address|tunnel-ipv6-address|tunnel-ipv4-network|tunnel-ipv6-network|tunnel-address|tunnel-network|dns-port|external-interface|external-interface-ipv4|external-interface-ipv6|advertise-ipv6-default-route) field=$arg ;;
  esac
done
case "$field" in
  tunnel-prefix) echo 10.200.0.1/16 ;;
  tunnel-ipv4-prefix) if [ "${TEST_IPV4_ENABLED:-1}" = 1 ]; then echo 10.200.0.1/16; fi ;;
  tunnel-ipv6-prefix) if [ -n "${TEST_TUNNEL_IPV6_PREFIX:-}" ]; then echo "$TEST_TUNNEL_IPV6_PREFIX"; fi ;;
  tunnel-ipv4-address) if [ "${TEST_IPV4_ENABLED:-1}" = 1 ]; then echo 10.200.0.1; fi ;;
  tunnel-ipv6-address) if [ -n "${TEST_TUNNEL_IPV6_PREFIX:-}" ]; then echo "${TEST_TUNNEL_IPV6_PREFIX%/*}"; fi ;;
  tunnel-ipv6-network) if [ -n "${TEST_TUNNEL_IPV6_PREFIX:-}" ]; then echo 2001:4860:100::/64; fi ;;
  tunnel-address) echo 10.200.0.1 ;;
  tunnel-network) echo 10.200.0.0/16 ;;
  dns-port) [ "${DNS_DISABLED:-0}" = 1 ] || echo 5353 ;;
  external-interface) echo eth0 ;;
  external-interface-ipv4) echo eth0 ;;
  external-interface-ipv6) if [ -n "${TEST_EXTERNAL_IPV6:-}" ]; then echo "$TEST_EXTERNAL_IPV6"; fi ;;
  advertise-ipv6-default-route) echo "${TEST_IPV6_ADVERTISE:-false}" ;;
esac
EOF
cat >"$tmp/bin/ip" <<'EOF'
#!/bin/sh
case " $* " in
  *" route show default "*)
    if [ "${ROUTE_DROPS_AFTER_FORWARD:-0}" = 1 ] && [ "$(cat "$JIEJIE_MASQUE_IP6_FORWARD_PATH")" = 1 ]; then exit 0; fi
    printf '%s\n' "default via fe80::1 dev eth1 proto ra metric 100 pref medium"
    ;;
esac
EOF
cat >"$tmp/bin/nft" <<'EOF'
#!/bin/sh
: "${NFT_LOG:=/dev/null}"
printf '%s\n' "$*" >> "$NFT_LOG"
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
UFW_LOG="$tmp/ufw.log" NFT_LOG="$tmp/nft.log" \
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

: >"$tmp/ufw-masque0.log"
printf '1\n' >"$tmp/ip_forward-masque0"
UFW_LOG="$tmp/ufw-masque0.log" NFT_LOG="$tmp/nft-masque0.log" JIEJIE_MASQUE_TUN_INTERFACE=masque0 \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-masque0" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null

: >"$tmp/ufw-invalid.log"
: >"$tmp/nft-invalid.log"
printf '1\n' >"$tmp/ip_forward-invalid"
if UFW_LOG="$tmp/ufw-invalid.log" NFT_LOG="$tmp/nft-invalid.log" JIEJIE_MASQUE_TUN_INTERFACE=foo0 \
  JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" \
  JIEJIE_MASQUE_NFT="$tmp/bin/nft" \
  JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
  JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-invalid" \
    "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null 2>"$tmp/invalid.stderr"; then
  echo 'invalid TUN interface override was accepted' >&2
  exit 1
fi
grep -F 'unsupported CONNECT-IP TUN interface override: runtime uses masque0' "$tmp/invalid.stderr"
if grep -Eq 'add|allow|delete' "$tmp/ufw-invalid.log" || [ -s "$tmp/nft-invalid.log" ]; then
  echo 'invalid TUN interface override mutated firewall state' >&2
  exit 1
fi
[ "$(cat "$tmp/ip_forward-invalid")" = 1 ]

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

# An RA-derived IPv6 WAN must retain its route after forwarding is enabled.
mkdir -p "$tmp/sysctl/eth1"
printf '1\n' >"$tmp/sysctl/eth1/accept_ra"
printf '0\n' >"$tmp/ip6_forward-ra"
printf '0\n' >"$tmp/ip_forward-ra"
TEST_IPV4_ENABLED=0 TEST_IPV6_ADVERTISE=true UFW_LOG="$tmp/ufw-ra.log" UFW_MODE=inactive \
TEST_TUNNEL_IPV6_PREFIX=2001:4860:100::1/64 TEST_EXTERNAL_IPV6=eth1 \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" JIEJIE_MASQUE_IP="$tmp/bin/ip" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-ra" JIEJIE_MASQUE_IP6_FORWARD_PATH="$tmp/ip6_forward-ra" \
JIEJIE_MASQUE_IPV6_SYSCTL_ROOT="$tmp/sysctl" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null
[ "$(cat "$tmp/sysctl/eth1/accept_ra")" = 2 ]
[ "$(cat "$tmp/ip6_forward-ra")" = 1 ]
[ "$(cat "$tmp/ip_forward-ra")" = 0 ]

# An active firewall with IPv6 disabled must fail before adding any rules.
printf 'IPV6=no\n' >"$tmp/ufw-default-no"
: >"$tmp/ufw-v6-disabled.log"
if TEST_IPV4_ENABLED=0 UFW_LOG="$tmp/ufw-v6-disabled.log" UFW_MODE=active \
  TEST_TUNNEL_IPV6_PREFIX=2001:4860:100::1/64 TEST_EXTERNAL_IPV6=eth1 \
  JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" JIEJIE_MASQUE_IP="$tmp/bin/ip" \
  JIEJIE_MASQUE_NFT="$tmp/bin/nft" JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
  JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-ra" JIEJIE_MASQUE_IP6_FORWARD_PATH="$tmp/ip6_forward-ra" \
  JIEJIE_MASQUE_IPV6_SYSCTL_ROOT="$tmp/sysctl" JIEJIE_MASQUE_UFW_IPV6_CONFIG="$tmp/ufw-default-no" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null 2>"$tmp/ufw-v6-disabled.stderr"; then
  echo 'network prepare accepted active UFW with IPv6 disabled' >&2
  exit 1
fi
grep -F 'UFW is active but IPv6 is disabled' "$tmp/ufw-v6-disabled.stderr"
if grep -Eq 'allow|delete' "$tmp/ufw-v6-disabled.log"; then
  echo 'UFW IPv6-disabled path mutated rules' >&2
  exit 1
fi

# With IPv6 enabled, the route rule must use the independent IPv6 WAN.
printf 'IPV6=yes\n' >"$tmp/ufw-default-yes"
: >"$tmp/ufw-v6-enabled.log"
TEST_IPV4_ENABLED=0 TEST_IPV6_ADVERTISE=true UFW_LOG="$tmp/ufw-v6-enabled.log" UFW_MODE=active \
TEST_TUNNEL_IPV6_PREFIX=2001:4860:100::1/64 TEST_EXTERNAL_IPV6=eth1 \
JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" JIEJIE_MASQUE_IP="$tmp/bin/ip" \
JIEJIE_MASQUE_NFT="$tmp/bin/nft" JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-ra" JIEJIE_MASQUE_IP6_FORWARD_PATH="$tmp/ip6_forward-ra" \
JIEJIE_MASQUE_IPV6_SYSCTL_ROOT="$tmp/sysctl" JIEJIE_MASQUE_UFW_IPV6_CONFIG="$tmp/ufw-default-yes" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null
grep -F 'route allow in on masque0 out on eth1 from 2001:4860:100::/64' "$tmp/ufw-v6-enabled.log"

# If the route disappears, fail closed and retain accept_ra=2 for recovery.
printf '1\n' >"$tmp/sysctl/eth1/accept_ra"
printf '0\n' >"$tmp/ip6_forward-loss"
if TEST_IPV4_ENABLED=0 TEST_IPV6_ADVERTISE=true UFW_MODE=inactive \
  TEST_TUNNEL_IPV6_PREFIX=2001:4860:100::1/64 TEST_EXTERNAL_IPV6=eth1 ROUTE_DROPS_AFTER_FORWARD=1 \
  JIEJIE_MASQUE_BIN="$tmp/bin/jiejie-masque" JIEJIE_MASQUE_IP="$tmp/bin/ip" \
  JIEJIE_MASQUE_NFT="$tmp/bin/nft" JIEJIE_MASQUE_UFW="$tmp/bin/ufw" \
  JIEJIE_MASQUE_IP_FORWARD_PATH="$tmp/ip_forward-ra" JIEJIE_MASQUE_IP6_FORWARD_PATH="$tmp/ip6_forward-loss" \
  JIEJIE_MASQUE_IPV6_SYSCTL_ROOT="$tmp/sysctl" \
  "$root/contrib/jiejie-masque-connect-ip-network-prepare" --config /dev/null 2>"$tmp/ra-loss.stderr"; then
  echo 'network prepare accepted a lost IPv6 WAN route' >&2
  exit 1
fi
grep -F 'IPv6 default route disappeared' "$tmp/ra-loss.stderr"
[ "$(cat "$tmp/sysctl/eth1/accept_ra")" = 2 ]
