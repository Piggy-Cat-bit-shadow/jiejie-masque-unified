# jiejie-masque v1.0.12

v1.0.12 is a maintenance and correctness release. It preserves the default
production path and does not introduce a protocol or performance redesign.

## Correctness fixes

- F-802: Linux optional TCP TX GRO rejects IPv4 options (`IHL != 20`); the
  default `tun_tx_gro=false` path is unaffected.
- F-803: serializes shared TX-GRO scratch-buffer allocation, aggregate and
  virtio-header construction, and `writev` completion with `txGROMu`.
- F-804: rejects IPv4 packets with MF set or any non-zero fragment offset while
  preserving ordinary DF-only packets.
- F-805: Session-NAT ICMP translation parses quoted IPv4 only for ICMP error
  types; Echo and other informational payloads remain opaque.
- F-806: fragmented outer ICMP translation changes only the outer address and
  IPv4 checksum; fragment payload and partial ICMP checksum state are preserved.
- F-807: the omitted CONNECT-IP stateless-reset key now defaults to
  `/var/lib/jiejie-masque-connect-ip/stateless-reset.key`, matching
  `StateDirectory=jiejie-masque-connect-ip`; explicit custom paths remain
  unchanged.
- F-808: the fake-command CONNECT-IP network-prepare/UFW regression suite is a
  formal branch and tag build gate.
- F-809: `JIEJIE_MASQUE_TUN_INTERFACE` values other than `masque0` fail before
  any host firewall, nftables, or forwarding mutation.
- F-810: optional TCP TX GRO enforces segment-size ordering. The first segment
  establishes `gso_size`; equal-size segments may continue, a final segment may
  be shorter and terminates the group, and a larger segment cannot follow the
  established size.

## Operational and CI hardening

- Active/inactive/missing UFW behavior, idempotence, project-owned stale-rule
  cleanup, add-failure retention, DNS-disabled cleanup, unrelated-rule
  preservation, and global-policy preservation are regression-tested.
- Pull-request targeting follows the repository default branch. GitHub Actions
  are pinned by full commit SHA, and dependency provenance is checked against
  the resolved module versions.
- TX-GRO, ICMP, race, Linux build, artifact metadata, release consistency, and
  same-artifact release gates remain enabled.

## Unchanged and deferred

- Core QUIC/HTTP/3 data paths, CONNECT-UDP, CONNECT-TCP, ownership model,
  retained RX model, final serialization copy, dependency pins, and congestion
  control are unchanged.
- `tun_tx_gro` remains disabled by default.
- N-06 remains documented/deferred: no DNS fragment tracker is implemented;
  use EDNS UDP payloads around 1232 bytes and TCP fallback for larger messages.
- N-09 remains an observability gap/deferred; no runtime UFW polling or
  automatic firewall rewrite was added.
