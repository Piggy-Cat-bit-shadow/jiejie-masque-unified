# Fork provenance

## quic-go

- Repository: `github.com/Piggy-Cat-bit-shadow/quic-go`
- Pinned commit: `509e22e92ae01477de7088738910f77da2631897`
- Upstream family: MetaCubeX/quic-go v0.61.1 development line
- License: MIT
- Local patches in the pinned fork: owned DATAGRAM buffers, retained receive
  budget, reusable borrowed parsing, native CUBIC selector, and the existing
  qlog/ECN/PMTU behavior used by CONNECT-IP.
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
- Pinned commit: `e645a82498ea70e3411b99e7a338ac740629abdd`
- License: MIT
- Used interfaces: owned packet-buffer send, borrowed packet-buffer receive,
  bounded DATAGRAM ownership, and CONNECT-IP address/route handling.
