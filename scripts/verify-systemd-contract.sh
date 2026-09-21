#!/usr/bin/env bash
set -euo pipefail

ip=contrib/jiejie-masque-connect-ip.service
need() { grep -q -F -- "$2" "$1" || { echo "missing $2 in $1" >&2; exit 1; }; }

for value in 'Type=simple' 'User=masque-lite' 'ExecStart=' 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' 'LimitNOFILE=65536' 'TimeoutStopSec=5s'; do need "$ip" "$value"; done
echo 'systemd-contract: passed'
