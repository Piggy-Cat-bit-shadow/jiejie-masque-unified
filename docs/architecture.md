# Architecture and Performance Invariants

This document records the frozen v1 architecture. The project is in maintenance
mode: make changes for bugs, security, or compatibility, not speculative
performance tuning.

## Data plane

The binary contains two independent services:

- CONNECT-IP uses HTTP/3 Extended CONNECT, Linux TUN, optional session NAT,
  packet ownership transfer, and a tunnel-local DNS gateway.
- CONNECT-UDP uses RFC 9298 CONNECT-UDP, HTTP Datagrams, bounded UDP relay
  flows, and HTTP Basic authentication.

## Queue and buffer limits

These values are release invariants:

| Component | Limit |
| --- | ---: |
| QUIC DATAGRAM send queue | 32 |
| QUIC DATAGRAM receive queue | 128 |
| HTTP/3 stream DATAGRAM receive queue | 32 |
| CONNECT-IP session outbound queue | 256 by default |
| Retained receive-buffer budget | 64 |
| CONNECT-IP PacketPool headroom | 9 bytes |
| TUN oversized-read sentinel | 1 byte |
| Default CONNECT-IP MTU | 1280 bytes |

The configured session queue remains bounded. The PacketPool headroom reserves
HTTP/3 quarter-stream-ID and CONNECT-IP Context ID prefixes; the sentinel makes
an oversized direct TUN read fail instead of accepting a truncated packet.

## Receive ownership

The normal receive path is:

```text
UDP packetBuffer
  -> decrypt
  -> reusable borrowed DATAGRAM parser scratch
  -> retained packetBuffer reference
  -> quic.DatagramBuffer
  -> HTTP/3 queue
  -> connect-ip PacketBuffer pointer view
  -> TUN
  -> Release
```

Normal receive payload copy count is zero. The first 64 retained buffers keep
their transport backing. When the retained budget is full, the 65th and later
eligible buffers use an exact-size compact fallback copy and release the
transport owner immediately. A full queue is a real drop, not a fallback-copy
case. Every owner, budget token, and packet-buffer reference is released once.

The parser owns reusable `DatagramFrame` metadata. Its `Data`, `DataOwner`,
`SendOwner`, and release state are reset before reuse. The retained owner is a
zero-allocation `retainedPacketBufferRef` pointer view. The CONNECT-IP
`PacketBuffer` is a named pointer view over `quic.DatagramBuffer`.

## Send ownership

The normal CONNECT-IP send path is:

```text
main PacketPool
  -> session outbound queue
  -> CONNECT-IP prefix
  -> HTTP/3 prefix
  -> QUIC SendDatagramOwned
  -> QUIC DATAGRAM queue
  -> final serialization
  -> ReleaseSendOwner
  -> QUIC packetBuffer
  -> send queue
  -> UDP / GSO
```

There are zero payload copies before QUIC serialization. The final
`DatagramFrame.Append` payload serialization copy is intentional and required
by the current contiguous QUIC packet, AEAD, header-protection, and GSO
architecture. The source PacketPool backing can be released after final
serialization because the encrypted packet is then held by the QUIC
`packetBuffer`.

## Pool lifetime and close rules

`sync.Pool` objects must never be manually resurrected after `Release` or
`Put`. A new generation is obtained only through `Get` or `Acquire`; tests must
not reset the refcount or release flag on an object already returned to a pool.

CONNECT-IP maps terminal local and remote closes to `CloseError`, preserving
`errors.Is(err, net.ErrClosed)` and the `Remote` bit. Context cancellation,
deadlines, `DatagramTooLargeError`, and unrelated errors retain their original
semantics. Queue close and drain paths release owned buffers exactly once.

CONNECT-IP receive handling releases an unsupported or invalid current
DATAGRAM and reads a fresh next DATAGRAM. It never loops on stale data.

## TUN offload and GSO

Both options default to disabled:

```yaml
server:
  tun_offload: false
  tun_tx_gro: false
```

When enabled, RX supports TCPv4/TCPv6 GSO splitting and TX supports ordered
TCPv4/TCPv6 GRO. UDP GRO/USO is not supported, and TX GRO requires TUN
offload. QUIC Linux UDP GSO remains enabled: multiple complete encrypted QUIC
packets are placed in one contiguous large buffer and sent with
`UDP_SEGMENT`.

## DNS and routing security

The CONNECT-IP DNS gateway listens only on the tunnel address and forwards UDP
and TCP to `127.0.0.1:53`. It has no public listener and no external-DNS
fallback.

CONNECT-UDP target policy resolves a hostname, validates the resulting allowed
IP snapshot, and dials only those validated addresses. TCP racing uses at most
the currently implemented four validated candidates; losing attempts are
cancelled and closed. The target is never resolved again after validation.

The supported congestion-controller values are `default` and `cubic`. BBR is
not included in v1.

## Zero-copy optimization boundary

The following are deliberately outside v1 and must not be reopened without
real profile and benchmark evidence:

- scatter/gather AEAD or custom crypto;
- external caller buffers as final QUIC packets;
- multi-iovec UDP GSO, `sendmmsg`, `MSG_ZEROCOPY`, or `io_uring` sends;
- disabling GSO or increasing syscall count to remove a memcpy;
- public `DatagramBuffer` pooling.

The complexity, safety, lifecycle, and GSO trade-offs exceed the expected
benefit. The frozen performance state is:

```text
normal RX payload copies                   0
normal TX copies before QUIC serialization 0
final QUIC serialization copies            1 intentional copy
borrowed parser benchmark                  0 B/op, 0 allocs/op
parser -> queue benchmark                  64 B/op, 1 alloc/op
CONNECT-IP receive benchmark               64 B/op, 1 alloc/op
```

