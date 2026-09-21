#!/usr/bin/env bash
set -euo pipefail

# Reproducible WAN matrix runner. It only changes the selected interface's
# temporary netem qdisc and restores it on exit. The benchmark itself is
# supplied by the operator so this script never invents localhost results.
#
# Required:
#   BENCHMARK_CMD='./run-mihomo-download.sh' \
#     sudo scripts/benchmark-connect-ip-matrix.sh eth0 results.csv
# Optional CONFIGURE_CMD is run before each case with CC exported;
# it may render/restart the disposable server configuration.

iface=${1:?interface required}
output=${2:?output CSV path required}
: "${BENCHMARK_CMD:?set BENCHMARK_CMD to the real client/download runner}"

cleanup() { tc qdisc del dev "$iface" root 2>/dev/null || true; }
trap cleanup EXIT INT TERM

printf 'timestamp,rtt_ms,loss,cc,benchmark_output\n' >"$output"
for rtt in 20 50 100 150 200; do
	for loss in 0% 0.1% 0.5% 1%; do
		for cc in cubic bbr; do
			export CC="$cc" RTT_MS="$rtt" LOSS="$loss"
			if [[ -n "${CONFIGURE_CMD:-}" ]]; then
				bash -c "$CONFIGURE_CMD"
			fi
			tc qdisc replace dev "$iface" root netem delay "${rtt}ms" loss "$loss"
			result=$(bash -c "$BENCHMARK_CMD" | tr '\n' ' ' | tr ',' ';')
			printf '%s,%s,%s,%s,"%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rtt" "$loss" "$cc" "$result" >>"$output"
		done
	done
done

echo "benchmark matrix complete: $output"
