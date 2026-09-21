#!/usr/bin/env bash
set -euo pipefail

ip=contrib/jiejie-masque-connect-ip.service
prepare_helper=contrib/jiejie-masque-connect-ip-network-prepare
need() { grep -q -F -- "$2" "$1" || { echo "missing $2 in $1" >&2; exit 1; }; }
absent() { ! grep -q -F -- "$2" "$1" || { echo "forbidden $2 in $1" >&2; exit 1; }; }

for value in 'Type=notify' 'User=masque-lite' 'EnvironmentFile=' 'check-config' 'network-prepare' 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' 'LimitNOFILE=65536' 'TimeoutStopSec=5s' 'NotifyAccess=main' 'StateDirectory='; do need "$ip" "$value"; done
need "$prepare_helper" 'network-prepare-info'
need "$prepare_helper" '--field external-interface'
need "$prepare_helper" '--field tunnel-prefix'
need "$prepare_helper" '--field external-interface-ipv4'
need "$prepare_helper" '--field external-interface-ipv6'
need "$prepare_helper" '--field tunnel-ipv4-prefix'
need "$prepare_helper" '--field tunnel-ipv6-prefix'
need "$prepare_helper" '--field tunnel-ipv4-address'
need "$prepare_helper" '--field tunnel-ipv6-address'
need "$prepare_helper" '--field tunnel-ipv6-network'
need "$prepare_helper" '--field dns-port'
if grep -Eq 'awk.*tunnel_ipv4|tunnel_ipv4.*(awk|sed|grep)' "$prepare_helper"; then
  echo 'network-prepare must not parse YAML tunnel_ipv4 in shell' >&2
  exit 1
fi
check=$(grep -n -F 'check-config' "$ip" | head -1 | cut -d: -f1)
prepare=$(grep -n -F 'network-prepare' "$ip" | head -1 | cut -d: -f1)
((check < prepare)) || { echo 'CONNECT-IP check-config must precede network-prepare' >&2; exit 1; }
echo 'systemd-contract: passed'
