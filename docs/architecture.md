# Architecture and frozen performance boundary

This document describes the v1.0.1 maintenance baseline. Runtime changes are
reserved for correctness, security, compatibility, ownership, or shutdown
bugs. Performance speculation is not a change request.

## Services and limits

The binary contains two independent MASQUE services:

- CONNECT-IP uses HTTP/3 Extended CONNECT, Linux TUN, optional session NAT,
  mTLS, and a tunnel-local DNS gateway.
- CONNECT-UDP uses RFC 9298 HTTP Datagrams, bounded UDP relay flows, target
  policy validation, and HTTP Basic authentication. CONNECT-TCP uses the same
  target policy and stream relay.

Frozen queue and buffer invariants:

| Component | Limit or layout |
| --- | --- |
| QUIC DATAGRAM send queue | 32 |
| QUIC DATAGRAM receive queue | 128 |
| HTTP/3 stream DATAGRAM receive queue | 32 |
| CONNECT-IP session outbound queue | 256 by default |
| CONNECT-IP retained receive budget | 64 |
| CONNECT-IP PacketPool headroom | 9 bytes |
| CONNECT-UDP owned backing | 1510 bytes |
| CONNECT-UDP H3 headroom | 8 bytes |
| CONNECT-UDP Context ID | 1 byte |
| CONNECT-UDP UDP read area | 1501 bytes |

The production defaults are one-minute flow/session reaping, one-hour idle
timeouts, CONNECT-UDP limits of 256 global and 64 per user, and a 256-packet
CONNECT-IP outbound queue. The example configs are the compatibility source
for these defaults.

When session NAT is enabled, a removed shadow address enters a pending-cleanup
state before it can be allocated again. Conntrack cleanup runs on two fixed
workers with a queue bounded by `max_sessions`; a full queue applies
backpressure without holding the session manager lock. `reuse_delay` starts
after the cleanup attempt completes, including failed attempts. Cleanup
shutdown stops new work, waits only for callbacks already running, and may
drop queued work as part of service shutdown.

## CONNECT-IP receive and send paths

The normal receive path is:

```text
UDP packetBuffer
  -> QUIC decrypt in place
  -> reusable borrowed DATAGRAM parser scratch
  -> retained packetBuffer reference
  -> quic.DatagramBuffer
  -> HTTP/3 stream queue
  -> connect-ip PacketBuffer pointer view
  -> Context ID strip/reslice and validation
  -> TUN Write
  -> Release
```

The retained budget is 64. Eligible packets 1 through 64 retain their
transport backing. When the budget is exhausted, the next eligible packet uses
an exact-size compact fallback copy and releases the original transport owner
immediately. A full receive queue drops the packet; it does not turn queue
overflow into a fallback copy. Normal application payload copying is zero.

The normal send path is:

```text
session PacketPool
  -> CONNECT-IP Context ID and HTTP/3 prefix in reserved headroom
  -> stateTrackingStream.SendDatagramBufferOwned
  -> rawConn.sendDatagramBufferOwned
  -> quic.Conn.SendDatagramOwned
  -> QUIC DATAGRAM send queue
  -> packetPacker / DatagramFrame.Append
  -> AEAD and header protection
  -> owner Release
```

`TrackStream` wires the owned callback into `stateTrackingStream`; the
production path does not rely on the legacy synchronous-copy fallback. There
are zero full payload copies before final QUIC serialization. The final
`DatagramFrame.Append` copy remains intentional because the current contiguous
packet, AEAD, header-protection, and GSO path requires it.

## CONNECT-UDP paths and ownership

Client to target:

```text
HTTP/3 DatagramBuffer
  -> ReceiveDatagramBuffer
  -> Context ID parse/reslice
  -> connected UDP Write
  -> DatagramBuffer.Release
```

Malformed context, unsupported context, oversized payload, write error, and
successful forwarding all release the received buffer exactly once.

Target to client:

```text
target UDP socket
  -> direct read into owned 1510-byte backing
  -> Context ID at offset 8
  -> SendDatagramBufferOwned with 8-byte H3 headroom
  -> stateTrackingStream / rawConn owned forwarding
  -> QUIC DATAGRAM queue
  -> final serialization and owner Release
  -> Proxy-level shared sync.Pool
```

The backing layout is:

```text
[0:8]     H3 quarter-stream-ID headroom
[8]       CONNECT-UDP Context ID 0
[9:1509]  up to 1500-byte UDP payload
[1509]    oversized sentinel
```

Exactly 1500 bytes are forwarded. A 1501-byte or larger UDP packet produces a
sentinel-sized read and is dropped without forwarding a truncated prefix. The
flow remains healthy for the next valid packet. Oversized drops use one
aggregate log at most every 30 seconds; normal packets do not call `time.Now`
for this logging path.

The owned pool is shared by all flows of one `Proxy`. `sync.Pool` is a
reusable cache, not a strict global memory bound. Live owned memory is roughly
the owned buffers queued by each relevant QUIC connection plus one active
target read per active relay; total live memory scales with concurrent flows
and connections. Recycled cached memory may remain available to the Go runtime
until garbage collection.

## Activity, policy, and cancellation

`Flow.Touch` performs only an atomic activity mark. The one-minute reaper
coalesces marks and materializes the timestamp. It rechecks activity before
closing an idle candidate; close, resource close, and admission release remain
exactly once.

CONNECT-UDP and CONNECT-TCP handlers pass the request context through DNS and
dial operations. Target policy resolves a hostname once, validates the
numeric result, and never passes the hostname to a dialer. UDP tries at most
four validated addresses sequentially; TCP races at most four validated
numeric addresses and closes losing attempts. Request cancellation stops DNS,
UDP dial fallback, and TCP dial work.

## TUN offload, congestion, and operations

TUN offload and TCP TX GRO default to false. UDP GRO/USO is not supported.
QUIC UDP GSO remains enabled. Congestion controller values are `default` and
`cubic`; `default` preserves baseline behavior, and BBR is not implemented.

QUIC startup reports requested/effective UDP socket buffers where the platform
allows inspection. Insufficient tuning is observable and non-fatal. The
systemd watchdog is a runtime heartbeat only; it does not prove QUIC event-loop
progress, packet forwarding, or remote reachability. The independent host
network deep probe covers forwarding/TUN/nft-NAT checks at its 30-second
interval and requires two consecutive failures before becoming fatal.

## Frozen optimization boundary

Measured baseline invariants are:

```text
CONNECT-IP normal RX application payload copies             0
CONNECT-IP TX pre-final payload copies                      0
CONNECT-UDP client->target application payload copies       0
CONNECT-UDP target->client pre-final payload copies         0
final QUIC serialization copies                             1 intentional
borrowed parser benchmark                                  0 B/op, 0 allocs/op
CONNECT-IP receive handle                                  64 B/op, 1 alloc/op
CONNECT-UDP owned pool steady state                        0 allocs/op
```

The current Flow.Touch benchmark is in the low-nanosecond range with zero
allocations, and the shared owned pool remains zero-allocation in steady state.
The final serialization copy, public DatagramBuffer pooling, sendmmsg,
recvmmsg, MSG_ZEROCOPY, io_uring, custom crypto, incremental checksum, new
congestion controllers, and UDP batching are deferred. `sendmmsg`/`recvmmsg`
are explicitly deferred, not release blockers: reopen them only with Linux
production profiling or reproducible syscall/CPU/latency evidence.
