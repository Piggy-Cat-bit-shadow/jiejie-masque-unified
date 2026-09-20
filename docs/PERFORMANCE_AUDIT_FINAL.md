# CONNECT-IP WAN performance audit

Status: pre-production code audit. Production defaults remain unchanged:
CUBIC, MTU 1280, session outbound queue 1024, QUIC DATAGRAM send/receive
queues 512/256, `tun_offload: false`, and `tun_tx_gro: false`.

The v1.0.16 VPS follow-up closed two deployment-observability gaps: the
CONNECT-IP unit now has the bind-only `CAP_NET_BIND_SERVICE` capability, and
server-side CONNECT-IP streams expose the maintained fork's identity-free QUIC
runtime snapshot. Socket logs explicitly show pre-tuning and post-
`Transport.Listen` values. Multi-connection telemetry is aggregate-only: sums
for additive counters, minimum non-zero PMTU/MinRTT, conservative maximum
latest/smoothed RTT, and `mixed` controller/state when active connections differ.

## Scope and path model

The server-to-client path is:

```text
masque0 TUN -> TUN batch reader -> packet.Parse / policy / NAT rewrite
-> bounded Session outbound queue -> sessionWriter -> connect-ip DATAGRAM
-> HTTP/3 -> quic-go DATAGRAM queue -> packet packer / CUBIC / pacer
-> bounded sendQueue -> UDP GSO -> socket -> WAN
```

| Stage | Blocking/backpressure | Copy/allocation | Lock/syscall/scheduling |
| --- | --- | --- | --- |
| TUN RX | bounded read; offload split is bounded | packet-pool slots | one TUN read per record; GSO can amortize packets |
| packet parser/policy | reject/drop only | no parser allocation | no lock |
| Session queue | bounded non-blocking enqueue; drop on full | pooled packet ownership | short `outboundMu`, atomic counters |
| sessionWriter | waits on bounded channel; closes on terminal error | owned DATAGRAM path avoids fallback copy when supported | one goroutine per session, bounded ready drain |
| QUIC DATAGRAM | bounded queue; producer backpressure when full | retained owner budget with bounded fallback copies | queue mutex and sender scheduling |
| pacer/sendQueue | congestion/pacing and kernel queue backpressure | packet buffers released after send | bounded send queue; UDP GSO syscall path |

No packet-level logging is enabled by default. Diagnostics are aggregate and
periodic; QLOG remains opt-in.

## Findings

### HIGH

None proven in the current environment. A real WAN and Linux kernel counters
are required to distinguish QUIC congestion, UDP socket drops, and TUN CPU cost.

### MEDIUM

- The next meaningful measurement is a Linux WAN A/B of plain TUN versus
  VNET_HDR/GSO/GRO. The implementation and correctness tests already exist,
  but this macOS development environment cannot prove syscall or CPU benefit.
- Socket buffer values are observable, but changing sysctls automatically is
  unsafe. Use the doctor output and `/proc/net/snmp`/`softnet_stat` on the VPS.
- The maintained quic-go fork now exposes identity-free runtime snapshots for
  cwnd, in-flight bytes, pacing, RTT, losses, reordering, queue pressure,
  PMTU, and GSO. These are the counters needed to classify the WAN bottleneck.

### LOW

- `sessionWriter` already drains a bounded ready burst and calls `Touch` once
  per successful burst, so there is no per-packet wall-clock read in the normal
  path.
- Session queue telemetry is atomic and the enqueue mutex protects the close,
  ownership, and bounded channel-drain invariant. No safe evidence justifies a
  replacement MPSC queue.
- IPv4 and ordinary IPv6 parsing take the version fast path; the bounded IPv6
  extension walker is only entered for extension-header packets.

### Not a bottleneck / intentionally unchanged

- `sendQueueCapacity=8`: matches the maintained upstream design; no local
  benchmark proves enlargement helps.
- QUIC DATAGRAM queues 512/256 and Session queue 1024: enlarging them would
  increase worst-case memory and can hide a downstream CUBIC/pacer bottleneck.
- No `sendmmsg`/`recvmmsg`, busy-spin, unsafe zero-copy, io_uring, real-time
  scheduling, or automatic sysctl changes were added.

## Benchmarks and profiles

Existing benchmark coverage includes session queue sizes and controlled drain,
packet pool versus copy, session-writer burst behavior, TUN slot refill, UDP
read/write batching, and manager lookup contention. The packet package now also
has `BenchmarkParseHotPaths` for IPv4 TCP/UDP, IPv6 TCP/UDP, IPv6 extensions,
and IPv6 fragment tails.

Run the reproducible local baseline with:

```bash
go test ./internal/connectip/packet -bench BenchmarkParseHotPaths -benchmem -count=5
go test ./internal/connectip/session -bench . -benchmem -count=3
go test ./cmd/jiejie-masque -bench . -benchmem -count=3
go test ./internal/connectudp -bench . -benchmem -count=3
```

Use CPU, memory, mutex, and block profiles only around a representative
benchmark or an actual Linux traffic run; synthetic loopback results are not a
WAN claim.

## VPS A/B required before changing defaults

1. Direct TCP/UDP control versus MASQUE CUBIC; test 100 KB, 1 MB, 10 MB,
   100 MB, 500 MB, and 1 GB downloads.
2. Record first-byte, 1/3/10-second throughput, steady goodput, loaded RTT
   p50/p95/p99, CPU, RSS, UDP errors, softnet drops, and the QUIC diagnostics.
3. Compare GSO and TUN offload combinations with defaults off.
4. Only after the clean CUBIC baseline, compare experimental BBRv3, PMTU
   ceilings, and offload settings. Roll back any option that improves
   throughput by inflating loaded RTT or loss.

## Release decision

This audit does not justify changing production defaults. The code is ready for
real Linux VPS measurement; the remaining questions are environmental
(`SO_RCVBUF`/`SO_SNDBUF`, NIC/kernel drops, GSO, WAN loss/reordering, and
controller behavior), not reasons to add unbounded queues or speculative
packet-path complexity.
