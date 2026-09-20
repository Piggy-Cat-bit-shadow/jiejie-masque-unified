# CONNECT-IP dual-stack architecture audit

This audit records the conservative boundary of the dual-stack change. IPv4
session NAT remains supported; IPv6 session NAT is intentionally rejected.

| Area | Current baseline | Decision |
|---|---|---|
| CONNECT-IP RX/TX | bounded session queue, owned packet buffers, bounded drains | P0: retain ownership and map both families to one session |
| CONNECT-UDP/TCP | implemented by connect-ip-go and QUIC | P2: no protocol rewrite without a measured defect |
| DATAGRAM, CUBIC, pacing, loss | maintained quic-go fork with bounded queues and CUBIC | P2: observe with qlog/benchmarks; no BBR insertion |
| TUN RX/TX, GSO/GRO | Linux offload already has IPv4/IPv6 flags; setup was IPv4-only | P0: configure both families; keep offload defaults unchanged |
| Packet parser | IPv4-only source/destination/port helpers | P0: bounded IPv4/IPv6 parser with extension-header and fragment rules |
| Session NAT | IPv4 shadow allocation and rewrite | P0: reject IPv6 + shadow mode; P1: design IPv6 NAT separately |
| Routing and host forwarding | IPv4 full route and forwarding check | P0: emit v4/v6 routes and family-specific forwarding checks |
| DNS gateway | one udp4/tcp4 listener | P0: one bounded UDP/TCP pair per configured tunnel address |
| nftables/UFW | IPv4 project-owned rules | P0: add family-aware ip6 rules and preserve comment-scoped cleanup |
| Socket buffers/QLOG | existing diagnostics | P2: measure only; do not tune blindly |
| Batching/sharding | bounded batch paths, no proven syscall bottleneck | P1: profile and A/B independently before recvmmsg/sharding |
| Mihomo output | existing schema is not a local contract | P1: do not invent IPv6 field names; verify against the target Mihomo release |
| PREF64/NAT64 | not a NAT64 service | REJECT: never advertise a synthetic PREF64 |

## Safety invariants

- IPv4-only YAML remains valid and retains the old public field names.
- A dual-stack session owns its IPv4 and IPv6 addresses atomically; either
  address resolves to the same bounded session queue.
- IPv6 extension parsing is capped at eight headers and 256 extension bytes;
  non-first fragments never expose a transport port.
- IPv6 addresses reject unspecified, multicast, loopback, mapped, and zoned
  forms. Client addresses must be `/32` or `/128` and belong to the matching
  server family prefix.
- The existing IPv4 shadow allocator is not used for IPv6, and no default
  NAT66 behavior is introduced.

## Deferred work

IPv6 shadow translation, a separate IPv6 pool allocator, `ADDRESS_REQUEST`
adoption from upstream connect-ip-go, QUIC congestion-control changes,
recvmmsg/sendmmsg, sharding, and adaptive queue sizing remain separate
experiments. They require independent packet/ownership or WAN benchmark
evidence and must not be bundled into the production dual-stack path.
