# jiejie-masque v1.0.13

v1.0.13 是一次 dependency / upstream synchronization 与 migration
correctness closure release，不是 performance release、zero-copy rewrite
或 new transport architecture。

## Changes

- QUIC foundation synchronized to the canonical quic-go 0.62 generation.
- CONNECT-IP synchronized to the 0.62-compatible upstream generation.
- Go toolchain updated to 1.26.8.
- YAML module migrated to `go.yaml.in/yaml/v3 v3.0.5`.
- GitHub Actions refreshed while retaining full-SHA pinning.
- Existing owned DATAGRAM, retained RX, PacketBuffer, bounded queue, and final
  serialization architecture preserved.

## Migration correctness closure

- F-901: TX-GRO owned capability drain gate.
- F-902: IPv4 options full-IHL checksum handling.
- F-903: legacy prepared-DATAGRAM fallback double-processing.
- F-904: terminal transport-close normalization.
- F-905: clean-clone and local-replace provenance reproducibility.
- F-906: dependency-fork CI validation attribution.
- F-907: owned DATAGRAM permanent-discard `SendOwner` release.
- F-908: plain CONNECT-IP `ReadPacket` / `WritePacket` terminal-close
  normalization.

## Preserved behavior and limits

The core dataplane architecture and ownership model are unchanged. QUIC send
and receive DATAGRAM queues remain 32 and 128; the HTTP/3 receive DATAGRAM
queue remains 32; the Session outbound queue remains 256; retained RX budget
remains 64; PacketPool headroom remains 9 bytes. The final serialization copy
remains intentional. UDP GSO remains enabled, `tun_tx_gro` remains
`default=false`, and `tun_offload` remains `default=false`.

Session NAT and DNS Gateway architecture are unchanged. CONNECT-TCP half-close
behavior is preserved. UFW/network-prepare design is preserved. Congestion
defaults are unchanged.

## Validation and deployment caveats

Real Mihomo client E2E was not executed in this release-validation environment.
Real Surge client E2E was not executed. Early-DATAGRAM pre-track behavior
remains a test/compatibility gap; no confirmed runtime defect was established.

F-701 host UFW/network-prepare integration depends on the binary's
`network-prepare-info`, the `contrib/jiejie-masque-connect-ip-network-prepare`
helper, and the systemd integration contract. Replacing only the binary does
not fully activate that host firewall integration; production upgrades must
deploy the exact v1.0.13 tagged helper/systemd integration together with the
exact v1.0.13 binary.

## Dependency provenance

```text
quic-go:      b6c72f4e72efb1a668cfa3dd29cf594350d59348
connect-ip:   e645a82498ea70e3411b99e7a338ac740629abdd
Go:           1.26.8
```

v1.0.12 remains unchanged. Production is not deployed by this release.
