# Fork provenance

## quic-go

- Repository: `github.com/Piggy-Cat-bit-shadow/quic-go`
- Sync branch: `sync/quic-go-v062-runtime`
- Pinned commit: `7f9c2206d3108f129514543350300555d5e649f7`
- Upstream family: MetaCubeX/quic-go v0.61.1 development line
- License: MIT
- Local patches in the pinned fork: owned DATAGRAM buffers, nonblocking and
  prefix-accepting batch submission, retained receive budget, reusable borrowed
  parsing, native CUBIC selector, runtime counters, and qlog/ECN/PMTU behavior.
- Sync baseline: the fork's existing MetaCubeX v0.62-compatible line, including
  the local DATAGRAM ownership and early-datagram lifecycle patches.
- Adopted upstream runtime fix: `fcb5bedb` (`CONNECTION_CLOSE` packet sizing
  accounts for 1-RTT AEAD overhead), applied as commit `e30fdc68`.
- Follow-up `45a73d78` is lint-only Go 1.27 cleanup in
  `http3/conn_test.go`; it changes no runtime behavior.
- Audited but deferred: `ea5cf308`, `c834ffae`, and `c6efd617` (Extended
  CONNECT and HTTP/3 `:path` parsing changes). They alter request-target
  semantics and need a separate compatibility review against this fork's
  MASQUE request-template behavior.
- This performance pass adds no unreviewed BBRv3 code to the fork. The current
  fork still selects native CUBIC through the existing connection hook; a
  future pluggable-controller change must be made and tested in the fork first,
  then consumed by this repository at a published commit.

The current IETF CCWG BBRv3 document is `draft-ietf-ccwg-bbr-06` (Experimental,
July 2026). It is treated as an algorithm specification reference, not as a
license to copy GPL-licensed Mihomo code or as evidence that a new QUIC port is
correct. No MetaCubeX/Mihomo BBR implementation is copied here.

## connect-ip-go

- Repository: `github.com/Piggy-Cat-bit-shadow/connect-ip-go`
- Sync branch: `sync/connect-ip-v0.3.0`
- Pinned commit: `456dcef1ecc9d92002dc72a97ba4f6c3f58410fe`
- License: MIT
- Used interfaces: owned packet-buffer send and prefix-accepting batch send,
  borrowed packet-buffer receive, bounded DATAGRAM ownership, and CONNECT-IP
  address/route handling.
- Sync baseline: local fork HEAD `31093245...`, preserving the local terminal
  error normalization, bounded capsule queue, packet-buffer APIs, and test
  timing adjustments.
- Replayed upstream v0.3.0 commits, in order: `cfcf8156` (require FQDNs in
  DNS_ASSIGN), `05c211713` (bound received address/route capsule entries), and
  `03f17e07` (serialize capsule writes and stream close). The latter two
  required manual conflict resolution in `conn.go`; local lifecycle and
  ownership behavior was retained.
- Post-v0.3 commits audited but deferred: `ea7d9f3` (ADDRESS_REQUEST API and
  state-machine expansion) and `a96891b` (client-side `NewClientConn`). The
  current service is server-side and does not need either compatibility change.
- `5f75fe3` only updates local test stream mocks for the retained `CancelWrite`
  interface; the later `ff8a7b5` refreshes this module's quic-go replacement with the
  synchronized quic-go fork. Neither changes the CONNECT-IP production API.
