#!/usr/bin/env bash
set -euo pipefail

ip=contrib/jiejie-masque-connect-ip.service
udp=contrib/jiejie-masque-connect-udp.service
need() { grep -q -F "$2" "$1" || { echo "missing $2 in $1" >&2; exit 1; }; }
absent() { ! grep -q -F "$2" "$1" || { echo "forbidden $2 in $1" >&2; exit 1; }; }

for value in 'Type=notify' 'User=masque-lite' 'EnvironmentFile=' 'check-config' 'network-prepare' 'CAP_NET_ADMIN' 'LimitNOFILE=65536' 'TimeoutStopSec=5s' 'WatchdogSec=' 'StateDirectory='; do need "$ip" "$value"; done
for value in 'Type=notify' 'User=masque' 'EnvironmentFile=' 'check-config' 'LimitNOFILE=65536' 'TimeoutStopSec=5s' 'WatchdogSec=' 'NotifyAccess=main' 'StateDirectory='; do need "$udp" "$value"; done
absent "$udp" 'CAP_NET_ADMIN'
absent "$udp" 'network-prepare'
check=$(grep -n -F 'check-config' "$ip" | head -1 | cut -d: -f1)
prepare=$(grep -n -F 'network-prepare' "$ip" | head -1 | cut -d: -f1)
((check < prepare)) || { echo 'CONNECT-IP check-config must precede network-prepare' >&2; exit 1; }
echo 'systemd-contract: passed'
