# jiejie-masque v1.0.0

## Highlights

- Unified single-binary CONNECT-IP and CONNECT-UDP MASQUE server.
- Owned-buffer CONNECT-IP send path with bounded queues.
- Zero-copy normal receive path with a bounded retained-buffer budget.
- Optional TCP TUN offload/GSO split and TCP TX GRO.
- QUIC UDP GSO preservation.
- Tunnel-local UDP/TCP DNS gateway.
- DNS-rebinding-safe target validation and bounded TCP racing.
- Mihomo CONNECT-IP configuration generation.

## Performance architecture

Normal QUIC-to-TUN payload copies are zero. Normal TUN-to-QUIC processing has
zero payload copies before QUIC serialization. One final intentional
`DatagramFrame.Append` serialization copy remains because the current QUIC
AEAD, header-protection, and GSO path requires a contiguous packet buffer.

## Reliability

The frozen implementation includes exactly-once ownership transfer, queue
close/drain handling, normalized terminal close errors, retained-budget
fallback copying, and MTU/ICMP handling. Runtime queue and buffer limits are
documented in `docs/architecture.md`.

## Verification

This release candidate was verified with Go tests, race tests, vet, module
verification, dependency/privacy/systemd/shell gates, Linux amd64 static ELF
build and release artifact checks, and GitHub Actions CI.

Runtime freeze base:

```text
main:          cf11f126dcfa1621dffc98b6595a4f77b33d5b88
connect-ip-go: 76018bfccf9fc03af9a966279d7e52fa036b063b
quic-go:       fd7d2285552d315feaf11ea103a215357ab38405
```

