# jiejie-masque v1.0.17

v1.0.17 adds an opt-in CONNECT-IP full-pipeline throughput diagnostic mode.
Production defaults remain unchanged: CUBIC, MTU 1280, Session outbound queue
1024, DATAGRAM queues 512/256, and TUN offload disabled.

## Diagnostics

- `diagnostics.pipeline.enabled: true` enables one-second aggregate snapshots;
  `format: json` emits machine-readable JSONL.
- TUN, Session, CONNECT-IP/HTTP/3 handoff, QUIC DATAGRAM, packet packing,
  sendQueue, UDP write/wire and GSO stages expose rates and bounded wait data.
- Maintained quic-go exposes DATAGRAM queue enqueue/dequeue bytes, non-empty
  duration, packet-packer counts, pacing wakeups, sendQueue writes and wire
  bytes through identity-free RuntimeStats.
- `diagnose-report FILE` summarizes JSONL stage peaks and largest observed gaps
  as evidence; it does not claim an automatic root cause.

## Boundaries

No queue, pacer, CUBIC, MTU, syscall strategy, BBR, offload default, payload
logging, client identity, destination, or private credential behavior changed.

## Maintained dependency pin

```text
quic-go replacement: v0.61.1-0.20260920123852-3a2faf7b603f
```
