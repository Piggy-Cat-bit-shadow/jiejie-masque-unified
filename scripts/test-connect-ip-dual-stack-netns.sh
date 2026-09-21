#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'dual-stack netns: SKIP (Linux required)'
  exit 0
fi
if [[ $(id -u) != 0 ]]; then
  echo 'dual-stack netns: SKIP (root/CAP_NET_ADMIN required)'
  exit 0
fi
if ! command -v ip >/dev/null || [[ ! -c /dev/net/tun ]]; then
  echo 'dual-stack netns: SKIP (iproute2 and /dev/net/tun required)'
  exit 0
fi

suffix="$$"
server="jm-s-${suffix}"
wan4="jm-4-${suffix}"
wan6="jm-6-${suffix}"
cleanup() {
  ip netns del "$server" 2>/dev/null || true
  ip netns del "$wan4" 2>/dev/null || true
  ip netns del "$wan6" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "$server"
ip netns add "$wan4"
ip netns add "$wan6"
ip link add "js4${suffix}" type veth peer name "jw4${suffix}"
ip link set "js4${suffix}" netns "$server"
ip link set "jw4${suffix}" netns "$wan4"
ip link add "js6${suffix}" type veth peer name "jw6${suffix}"
ip link set "js6${suffix}" netns "$server"
ip link set "jw6${suffix}" netns "$wan6"

ip -n "$server" link set lo up
ip -n "$wan4" link set lo up
ip -n "$wan6" link set lo up
ip -n "$server" addr add 198.18.4.1/30 dev "js4${suffix}"
ip -n "$wan4" addr add 198.18.4.2/30 dev "jw4${suffix}"
ip -n "$server" -6 addr add 2001:db8:6::1/64 dev "js6${suffix}" nodad
ip -n "$wan6" -6 addr add 2001:db8:6::2/64 dev "jw6${suffix}" nodad
ip -n "$server" link set "js4${suffix}" up
ip -n "$wan4" link set "jw4${suffix}" up
ip -n "$server" link set "js6${suffix}" up
ip -n "$wan6" link set "jw6${suffix}" up

dump_ipv6_state() {
  local ns=$1 dev=$2 label=$3
  echo "--- ${label}: IPv6 addresses on ${dev} ---" >&2
  ip -n "$ns" -6 addr show dev "$dev" >&2 || true
  echo "--- ${label}: tentative IPv6 addresses ---" >&2
  ip -n "$ns" -6 addr show tentative >&2 || true
  echo "--- ${label}: IPv6 multicast memberships on ${dev} ---" >&2
  ip -n "$ns" -6 maddr show dev "$dev" >&2 || true
  echo "--- ${label}: accept_dad ---" >&2
  ip netns exec "$ns" sysctl net.ipv6.conf.all.accept_dad >&2 || true
  ip netns exec "$ns" sysctl net.ipv6.conf.default.accept_dad >&2 || true
}

# Capture the address/DAD and multicast state before the first NDP exchange.
dump_ipv6_state "$server" "js6${suffix}" server
dump_ipv6_state "$wan6" "jw6${suffix}" WAN

# First prove on-link NDP and basic IPv6 connectivity independently from
# forwarding and the synthetic routed-prefix source.
if ! v6_link_ping=$(ip netns exec "$server" ping -6 -n -c 1 -W 2 -I 2001:db8:6::1 2001:db8:6::2 2>&1); then
  echo "dual-stack netns: on-link IPv6 NDP ping failed: $v6_link_ping" >&2
  dump_ipv6_state "$server" "js6${suffix}" server
  dump_ipv6_state "$wan6" "jw6${suffix}" WAN
  ip -n "$server" -6 neigh show dev "js6${suffix}" >&2 || true
  ip -n "$wan6" -6 neigh show dev "jw6${suffix}" >&2 || true
  echo '--- waiting 1.3s and retrying once to diagnose transient DAD/NDP ---' >&2
  sleep 1.3
  if v6_link_retry=$(ip netns exec "$server" ping -6 -n -c 1 -W 2 -I 2001:db8:6::1 2001:db8:6::2 2>&1); then
    echo 'dual-stack netns: on-link retry passed after initial failure (transient setup race suspected)' >&2
  else
    echo "dual-stack netns: on-link retry also failed: $v6_link_retry" >&2
  fi
  dump_ipv6_state "$server" "js6${suffix}" server
  dump_ipv6_state "$wan6" "jw6${suffix}" WAN
  exit 1
fi

ip -n "$server" tuntap add dev masque0 mode tun
ip -n "$server" addr add 10.200.0.1/24 dev masque0
ip -n "$server" addr add 10.200.0.2/32 dev masque0
ip -n "$server" -6 addr add 2001:db8:200::1/64 dev masque0 nodad
ip -n "$server" -6 addr add 2001:db8:200::2/128 dev masque0 nodad
ip -n "$server" -6 addr add fd00:200::1/128 dev masque0 nodad
ip -n "$server" link set masque0 mtu 1280 up
ip -n "$server" route add default via 198.18.4.2 dev "js4${suffix}"
ip -n "$server" -6 route add default via 2001:db8:6::2 dev "js6${suffix}" metric 100
ip -n "$wan4" route add 10.200.0.0/24 via 198.18.4.1
ip -n "$wan6" -6 route add 2001:db8:200::/64 via 2001:db8:6::1

ip netns exec "$server" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$server" sysctl -qw net.ipv6.conf.all.forwarding=1
# Synthetic RA-enabled WAN setup: forwarding must coexist with accept_ra=2,
# and the selected IPv6 default route must remain present.
ip netns exec "$server" sysctl -qw "net.ipv6.conf.js6${suffix}.accept_ra=2"
ip netns exec "$server" ip -6 route show default | grep -F "dev js6${suffix}" >/dev/null

v4_route=$(ip netns exec "$server" ip route get 198.18.4.2 from 10.200.0.2)
v6_route=$(ip netns exec "$server" ip -6 route get 2001:db8:6::2 from 2001:db8:200::2)
if [[ $v4_route != *"dev js4${suffix}"* ]]; then
  echo "dual-stack netns: IPv4 route lookup unexpected: $v4_route" >&2
  exit 1
fi
if [[ $v6_route != *"dev js6${suffix}"* ]]; then
  echo "dual-stack netns: IPv6 route lookup unexpected: $v6_route" >&2
  exit 1
fi
if ! v4_ping=$(ip netns exec "$server" ping -n -c 1 -W 2 -I 10.200.0.2 198.18.4.2 2>&1); then
  echo "dual-stack netns: IPv4 synthetic egress ping failed: $v4_ping" >&2
  exit 1
fi
if ! v6_ping=$(ip netns exec "$server" ping -6 -n -c 1 -W 2 -I 2001:db8:200::2 2001:db8:6::2 2>&1); then
  echo "dual-stack netns: first IPv6 synthetic egress ping failed: $v6_ping" >&2
  echo '--- immediate IPv6 diagnostics ---' >&2
  ip -n "$server" -6 addr show >&2 || true
  ip -n "$server" -6 route show >&2 || true
  ip -n "$server" -6 neigh show >&2 || true
  ip -n "$server" -6 maddr show >&2 || true
  ip -n "$server" -details link show >&2 || true
  ip -n "$wan6" -6 addr show >&2 || true
  ip -n "$wan6" -6 route show >&2 || true
  ip -n "$wan6" -6 neigh show >&2 || true
  ip -n "$wan6" -6 maddr show >&2 || true
  ip -n "$wan6" -details link show >&2 || true
  for ns in "$server" "$wan6"; do
    for key in disable_ipv6 accept_dad forwarding accept_ra; do
      ip netns exec "$ns" sysctl "net.ipv6.conf.all.${key}" >&2 || true
      ip netns exec "$ns" sysctl "net.ipv6.conf.default.${key}" >&2 || true
    done
  done
  echo '--- waiting 1.3s and retrying once to diagnose transient DAD/NDP ---' >&2
  sleep 1.3
  if ! v6_retry=$(ip netns exec "$server" ping -6 -n -c 1 -W 2 -I 2001:db8:200::2 2001:db8:6::2 2>&1); then
    echo "dual-stack netns: IPv6 synthetic egress retry failed: $v6_retry" >&2
    echo 'server route:' >&2
    ip -n "$server" -6 route get 2001:db8:6::2 from 2001:db8:200::2 >&2 || true
    echo 'WAN return route:' >&2
    ip -n "$wan6" -6 route get 2001:db8:200::2 >&2 || true
    echo 'server IPv6 neighbors:' >&2
    ip -n "$server" -6 neigh show dev "js6${suffix}" >&2 || true
    echo 'WAN IPv6 neighbors:' >&2
    ip -n "$wan6" -6 neigh show dev "jw6${suffix}" >&2 || true
    exit 1
  fi
  echo 'dual-stack netns: IPv6 synthetic egress retry passed after initial failure' >&2
  exit 1
fi

check_dynamic_neighbor() {
  local ns=$1 dev=$2 target=$3 neighbor
  neighbor=$(ip -n "$ns" -6 neigh show to "$target" dev "$dev")
  case "$neighbor" in
    *PERMANENT*|*INCOMPLETE*|*FAILED*|'')
      echo "dual-stack netns: invalid dynamic NDP state for ${target}: ${neighbor:-missing}" >&2
      exit 1
      ;;
    *REACHABLE*|*STALE*|*DELAY*) ;;
    *)
      echo "dual-stack netns: unexpected NDP state for ${target}: $neighbor" >&2
      exit 1
      ;;
  esac
}
check_dynamic_neighbor "$server" "js6${suffix}" 2001:db8:6::2
check_dynamic_neighbor "$wan6" "jw6${suffix}" 2001:db8:6::1
if ! ip -n "$server" -6 addr show dev masque0 | grep -F 'fd00:200::1/128' >/dev/null; then
  echo 'dual-stack netns: tunnel-local IPv6 DNS address missing from TUN' >&2
  exit 1
fi

echo 'dual-stack netns: PASS (synthetic IPv4/IPv6 routed egress, distinct WAN interfaces, TUN-local IPv6 host route, forwarding/RA sysctl)'
