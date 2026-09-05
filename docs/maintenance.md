# Maintenance and release guide

The v1.0.2 runtime baseline is frozen at
`3a07c4be6ad027620cfdaddad13a53609b7c0a06`. Accept correctness, security,
compatibility, ownership, shutdown, and release-metadata fixes. Do not reopen
speculative performance work without reproducible production evidence.

Changes to `mihomo-config` key encodings must be checked against the consumer
parser contract: client `private-key` is SEC1 EC DER Base64, while the server
endpoint `public-key` is PKIX/SubjectPublicKeyInfo DER Base64. Client
authentication `public_key` values remain raw uncompressed P-256 point Base64.

The CONNECT-IP DNS gateway accepts UDP requests up to 4096 bytes and drops
larger datagrams before upstream relay. The privileged network-prepare helper
must obtain `server.tunnel_ipv4` through `network-prepare-info`; it must not
parse YAML itself. Public-repository checks scan all tracked files for
high-confidence private-key material and scan public documentation/configuration
for non-example addresses and domains.

CONNECT-IP DNS-over-TCP keeps one downstream connection open for sequential or
pipelined length-prefixed queries, processing them in order. Each query still
uses its own upstream TCP connection; the existing downstream concurrency and
timeout bounds remain in force.

CONNECT-UDP/CONNECT-TCP `allow_private: false` follows the IANA
Special-Purpose Address Registries' `Globally Reachable` semantics, including
more-specific globally reachable exceptions. IPv4-mapped IPv6 addresses are
unmapped before classification. The static address snapshot is maintained
manually; runtime and CI do not fetch IANA.

## Exact dependency provenance

```text
main runtime baseline:             3a07c4be6ad027620cfdaddad13a53609b7c0a06
connect-ip-go:                     57381910bb5fca61b4d3d03fe098929bc294ad11
  pseudo-version:                  v0.0.0-20260905040753-57381910bb5f
quic-go:                           ac11e929d6decc0eb5f8235259ef82671dad3bca
  pseudo-version:                  v0.0.0-20260905040559-ac11e929d6de
```

The main module and connect-ip-go both replace the MetaCubeX quic-go module
with the same Piggy-Cat-bit-shadow fork checkpoint. Do not use `go get -u`.
Any dependency change requires upstream diff review, targeted tests, race,
vet, benchmark comparison, module verification, and a new main pin.

## Ownership and lifecycle checks

Session-NAT cleanup is a bounded asynchronous resource, not an unbounded
goroutine-per-session path. Pending shadow addresses remain unavailable until
their cleanup attempt completes; only then does `reuse_delay` begin. Keep the
two-worker executor, its `max_sessions`-derived queue, queue-full backpressure,
error observability, and explicit shutdown lifecycle covered by deterministic
tests. A normal cleanup error must not terminate a worker; queued cleanup may
be dropped only while shutting down.

The v1.0.2 maintenance batches are closed: Mihomo consumer-key contracts,
DNS/config/YAML/privacy correctness, public globally reachable target policy
with a 10-second establishment deadline, and bounded Session-NAT cleanup.
The final runtime baseline is the SHA above; a later release-preparation SHA
contains documentation and release metadata only.

Before changing ownership code, cover queue-full drop, close drain, send
rejection, `DatagramTooLargeError`, malformed input, duplicate Release, and
exactly-once transfer. Never reset a release flag or resurrect an object after
it has been returned to `sync.Pool`; a new generation comes only from
`Acquire`/`Get`.

The CONNECT-IP retained receive budget is 64. The CONNECT-IP session outbound
queue is 256 by default. QUIC DATAGRAM send/receive queues are 32/128 and the
HTTP/3 stream DATAGRAM queue is 32. CONNECT-UDP uses a Proxy-level shared
1510-byte pool; this is reusable cache, not a strict global memory bound.

## Required validation

From the final release commit:

```sh
test -z "$(gofmt -l .)"
go mod tidy -diff
go mod verify
go test ./...
go test -race ./...
go vet ./...
bash -n scripts/*.sh
bash scripts/verify-deps.sh
bash scripts/verify-public-repo.sh
bash scripts/verify-public-repo-selftest.sh
bash scripts/verify-systemd-contract.sh
```

Also run the focused CONNECT-IP and CONNECT-UDP ownership, malformed-input,
Flow.Touch/Reap, cancellation, fallback, and notify tests with suitable
`-count` stress. Run the borrowed parser, CONNECT-IP receive, Flow.Touch, and
owned-pool benchmarks for allocation regressions; do not turn machine-specific
nanosecond values into CI gates.

## Release artifact

Build the static stripped Linux amd64 artifact with:

```sh
VERSION=1.0.2 OUTPUT=dist/jiejie-masque-linux-amd64 scripts/build-release.sh
sha256sum dist/jiejie-masque-linux-amd64 > dist/jiejie-masque-linux-amd64.sha256
sha256sum -c dist/jiejie-masque-linux-amd64.sha256
```

Verify x86-64 ELF, static linkage, stripped symbols, exact byte size, and the
embedded version/commit. Upload only the binary and checksum to the GitHub
Release. Do not include private paths, credentials, hostnames, or deployment
identifiers.

## Frozen optimization boundary

Server dataplane performance is closed for v1.0.2. Synthetic churn can expose
Manager mutex activity, but current benchmarks do not justify lock architecture
changes. The final local reference run was approximately 73.6 ns/op for lookup,
72.9 ns/op under churn, and 1.09 us/op for the cooling-heavy allocator; the
machine-specific values are evidence for this audit, not CI thresholds.
`MANAGER LOCK REFACTOR NOT JUSTIFIED`.

Normal CONNECT-IP RX and CONNECT-UDP client-to-target application payload
copies are zero. Normal CONNECT-IP TX and CONNECT-UDP target-to-client paths
have zero full payload copies before final QUIC serialization. The final
`DatagramFrame.Append` copy remains intentional. `sendmmsg`/`recvmmsg`,
MSG_ZEROCOPY, io_uring, public DATAGRAM pooling, custom crypto, incremental
checksum, new congestion controllers, and UDP batching are deferred and are
not release blockers. Reopen them only with Linux production profile,
syscall/CPU/latency, allocation, qlog, or packet-loss evidence.

## Local environment caveats

Constrained local UDP/TLS/TLS-config environments can expose failures in
upstream-style quic tests that are unrelated to this release: `TestDial`'s
four loopback variants may time out; `TestTransportClose` may return too early;
`TestTransportAndDialConcurrentClose` may see the intentionally incomplete TLS
config before the transport-close error; HTTP/3 self-tests may reject an empty
client TLS ServerName; and race instrumentation can make
`TestFrameParserAllocs/STREAM` report allocations. The known `gofmt -l` files
`qlog/benchmark_test.go` and `quicvarint/varint_test.go` are inherited fork
formatting exceptions. Confirm targeted packages, main CI, and release gates
before classifying such a failure as a product defect. This is a validation
caveat, not a reason to alter runtime behavior during a release audit.

## v1.0.3 third-audit closure

The v1.0.3 runtime baseline is `5d5e25ec46b0fb8e6300040760da9a019ccbd8c7`.
The third-audit release closure changes documentation and release metadata only;
the runtime baseline remains frozen.

| Finding | Final status |
| --- | --- |
| F-301 | FIXED |
| F-302 | DEFERRED / REPRODUCTION REQUIRED |
| F-303 | FIXED |
| F-304 | FIXED |
| H-305 | MEASURE FIRST |
| H-306 | PRODUCTION A/B REQUIRED |

F-301's effective CONNECT-UDP admission identity is explicit `Credential.Name`
when non-empty, otherwise `Username`; both usernames and effective identities
must be unique. F-303 consumes wrapped `connectip.CloseError` values with
`errors.Is` for `context.Canceled`, `net.ErrClosed`, and `io.ErrClosedPipe`.
F-304 supports sequential and pipelined length-prefixed DNS-over-TCP messages
on one downstream connection, processes them in order, and opens one upstream
TCP connection per query. Clean EOF and idle timeout do not increment DNS
gateway Errors; malformed or failed message operations do.

F-302 remains a plausible cross-process Session-NAT stale-conntrack lifecycle
risk, but has not been reproduced as a user-visible production failure and does
not justify a speculative startup conntrack flush. H-305 remains a product
profile measurement decision, and H-306 requires production A/B measurement;
neither changes runtime code in v1.0.3.

The IANA IPv4 and IPv6 special-purpose policy snapshots are verified current
through 2025-10-09. The frozen dataplane ownership, queue, buffer, cleanup,
PacketPool, and final serialization-copy invariants remain unchanged.

## v1.0.4 candidate — maintenance batch 1

This candidate reopens only CONNECT-TCP lifecycle handling, CONNECT-IP config
loading, and network-preparation config propagation:

| Finding | Candidate status |
| --- | --- |
| F-401 | FIXED |
| F-402 | FIXED |
| F-403 | FIXED |
| F-404 | REPRODUCTION REQUIRED |
| F-405 | OPEN |
| F-406 | OPEN |

CONNECT-TCP now treats directional EOF as half-close: client-to-target EOF
uses TCP `CloseWrite`, target-to-client EOF closes only the HTTP/3 send
direction, and only abnormal copy errors trigger bidirectional teardown.
CONNECT-IP semantic YAML defaults and validation remain solely in
`config.Load`; the mode envelope is routing-only. The network-prepare helper
supports fixed `tunnel-prefix` and `external-interface` field queries while
retaining the legacy no-field tunnel-prefix output and the CLI/env/YAML/route
interface precedence. F-404, release provenance, README drift, H-305, and H-306
are intentionally outside this batch.
