#!/usr/bin/env bash
# Reproduces the kernel half of F-404/F-302 with real UDP traffic and NAT.
# It is deliberately manual: it needs Linux root (or CAP_NET_ADMIN) and must
# never run as part of ordinary `go test ./...`.
set -euo pipefail

mode=${1:-f404}
case "$mode" in f404|f302) ;; *) echo "usage: $0 [f404|f302]" >&2; exit 2 ;; esac

[[ $(uname -s) == Linux ]] || { echo 'SKIP: Linux is required'; exit 0; }
cap_eff=$(awk '/^CapEff:/ { print $2 }' /proc/self/status)
(( (16#$cap_eff & (1 << 12)) != 0 )) || { echo 'SKIP: CAP_NET_ADMIN is required'; exit 0; }
for tool in ip nft conntrack python3; do
  command -v "$tool" >/dev/null || { echo "SKIP: $tool is required"; exit 0; }
done

suffix=$$
client=jm-client-$suffix
router=jm-router-$suffix
server=jm-server-$suffix
server_pid=
cleanup() {
  [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null || true
  ip netns del "$client" 2>/dev/null || true
  ip netns del "$router" 2>/dev/null || true
  ip netns del "$server" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$client"
ip netns add "$router"
ip netns add "$server"
ip link add c0 type veth peer name r0
ip link add r1 type veth peer name s0
ip link set c0 netns "$client"
ip link set r0 netns "$router"
ip link set r1 netns "$router"
ip link set s0 netns "$server"

ip -n "$client" addr add 10.244.0.2/24 dev c0
ip -n "$client" link set lo up
ip -n "$client" link set c0 up
ip -n "$client" route add default via 10.244.0.1
ip -n "$router" addr add 10.244.0.1/24 dev r0
ip -n "$router" addr add 198.18.0.1/24 dev r1
ip -n "$router" link set lo up
ip -n "$router" link set r0 up
ip -n "$router" link set r1 up
ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1
ip -n "$server" addr add 198.18.0.2/24 dev s0
ip -n "$server" link set lo up
ip -n "$server" link set s0 up
ip -n "$server" route add default via 198.18.0.1
ip netns exec "$router" nft add table ip jm_repro
ip netns exec "$router" nft 'add chain ip jm_repro postrouting { type nat hook postrouting priority srcnat; }'
ip netns exec "$router" nft add rule ip jm_repro postrouting oifname r1 ip saddr 10.244.0.2 masquerade

ip netns exec "$server" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.18.0.2", 19000))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data, peer)
' &
server_pid=$!

send() {
  local payload=$1
  ip netns exec "$client" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.244.0.2", 32000))
s.settimeout(2)
s.sendto(sys.argv[1].encode(), ("198.18.0.2", 19000))
assert s.recv(2048).decode() == sys.argv[1]
' "$payload"
}

send owner-one
flow='src=10.244.0.2 dst=198.18.0.2 sport=32000 dport=19000'
ip netns exec "$router" conntrack -L -p udp | grep -F "$flow" >/dev/null || {
  echo 'FAIL: expected NAT conntrack flow was not created' >&2; exit 1;
}
echo "created NAT flow for first session owner ($mode)"

if [[ $mode == f302 ]]; then
  # This is a partial restart reproducer: a fresh client process obtains the
  # same tuple while router conntrack deliberately survives. It does not claim
  # to persist or restart the MASQUE daemon itself.
  echo 'PARTIAL F-302: simulating fresh client process while kernel conntrack survives'
else
  # Simulate a cleanup command that failed: deliberately leave the entry in
  # place before handing the exact same address/tuple to the next owner.
  echo 'simulating failed conntrack cleanup; stale entry is intentionally retained'
fi

send owner-two
ip netns exec "$router" conntrack -L -p udp | grep -F "$flow" >/dev/null || {
  echo 'FAIL: stale conntrack flow unexpectedly disappeared' >&2; exit 1;
}
echo 'REPRODUCED: a new owner can share an extant kernel conntrack tuple after reuse.'
echo 'F-404 mitigation: the running manager quarantines any address whose cleanup callback fails.'
echo 'F-302 remains deferred: this is a partial kernel-state reproducer, not a daemon-restart proof.'
