#!/usr/bin/env bash
set -euo pipefail

# Explicit, reversible WAN impairment helper. It never changes sysctl or starts
# services. Example: sudo scripts/benchmark-netem.sh eth0 150ms 0.5% 10ms
iface=${1:?interface required}; delay=${2:?delay required}; loss=${3:?loss required}; jitter=${4:-0ms}
cleanup() { tc qdisc del dev "$iface" root 2>/dev/null || true; }
trap cleanup EXIT INT TERM
tc qdisc replace dev "$iface" root netem delay "$delay" "$jitter" loss "$loss"
echo "netem active on $iface; run your Mihomo/curl or iperf3 sample now; Ctrl-C restores qdisc"
while :; do sleep 1; done
