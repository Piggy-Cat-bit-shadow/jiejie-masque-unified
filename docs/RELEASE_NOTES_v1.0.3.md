# jiejie-masque v1.0.3

Third-audit maintenance release. No dataplane architecture redesign.

The v1.0.3 runtime baseline is
`5d5e25ec46b0fb8e6300040760da9a019ccbd8c7`. The final release commit adds
release documentation and metadata only.

## CONNECT-UDP identity accounting

CONNECT-UDP multi-user configurations now reject duplicate effective
admission/accounting identities. The effective identity is explicit `Name`
when present, otherwise `Username`. This closes identity-accounting collisions;
it is not an authentication-bypass fix.

## CONNECT-IP close classification

CONNECT-IP session shutdown classification now consumes wrapped close semantics
with `errors.Is`, preventing normal local/remote close conditions from being
mislabeled as read/write failures. Arbitrary errors remain observable as
read/write failures.

## DNS-over-TCP compatibility

Tunnel-local DNS-over-TCP now supports multiple sequential or pipelined
length-prefixed DNS messages on one downstream TCP connection. Messages are
processed sequentially and responses remain in order. Each DNS query still
uses an independent upstream TCP connection; there is no upstream connection
pool, persistent upstream session, or transaction multiplexing.

TCP framing remains a two-byte network-order length followed by the DNS
message. DNS messages must be at least 12 bytes and may use the full uint16
framing range; the UDP 4096-byte limit is unchanged and is not applied to TCP.
Successfully relayed messages increment Queries. Malformed or failed message
operations increment Errors, while clean EOF and idle downstream timeout are
normal connection termination.

## Deferred third-audit findings

- F-302: DEFERRED / REPRODUCTION REQUIRED. A possible cross-process Session-NAT
  stale-conntrack generation boundary remains a production validation item.
  No user-visible failure has been demonstrated, so no speculative startup
  conntrack flush is included.
- H-305: MEASURE FIRST / PRODUCT PROFILE DECISION.
- H-306: PRODUCTION A/B REQUIRED.

## Explicit non-changes

The CONNECT-IP and CONNECT-UDP packet dataplanes, QUIC CID/migration and UDP
SNI Router architecture, Session-NAT cleanup lifecycle, `cleanupPending`, queue
and buffer constants, Mihomo congestion profile, dependency pins, and network-
prepare startup behavior are unchanged. No production deployment or conntrack
experiment is part of this release.

The IANA IPv4 and IPv6 special-purpose policy snapshots remain verified current
through 2025-10-09.

## Dependency provenance

- connect-ip-go: `57381910bb5fca61b4d3d03fe098929bc294ad11`
  (`v0.0.0-20260905040753-57381910bb5f`)
- quic-go: `ac11e929d6decc0eb5f8235259ef82671dad3bca`
  (`v0.0.0-20260905040559-ac11e929d6de`)

## Validation

The final release commit is validated by the repository's full test, race,
vet, module, dependency, privacy, systemd, shell, and Linux amd64 release
gates. Historical release tags remain unchanged.
