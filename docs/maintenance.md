# Maintenance and release guide

Current released version: `v1.0.10`

v1.0.9 runtime correctness fix:
`66cb3bd1057d93f81bb5858b0eabb7fe865ca251`

F-601 runtime fix:
`e6ceea21360d5a4e0cddfe86719d13774a82d0ca`

v1.0.8 networking/runtime behavior baseline:
`dcbd06708cf80a0f55bc5a0f0bed8660a26fd655`

v1.0.8 final release tag target:
`14ed18241268a07bb462792b348dd27e5c24ce8b`

v1.0.3 runtime baseline:
`5d5e25ec46b0fb8e6300040760da9a019ccbd8c7`

v1.0.3 release commit:
`1203497d5b21b85cacea63c5312465a6fe7085c2`

v1.0.4 release-preparation baseline:
`dcbd06708cf80a0f55bc5a0f0bed8660a26fd655`

Formal releases are tag-triggered GitHub Actions builds. The annotated tag
provides the version and exact commit; the build job produces and validates one
artifact, and the release job uploads that same artifact without rebuilding.
Branch and pull-request artifacts are candidate artifacts, not release assets.

## v1.0.10 release — F-601 and Chinese documentation

F-601 preserves the TCP TX GRO boundary after a segment carrying PSH is
absorbed: that segment may remain the final segment of the current aggregate,
but subsequent segments start a later group. The fix is covered by Linux
`WriteBatch` regressions for IPv4 and IPv6, including intermediate, final,
initial, and multiple PSH boundaries. `tun_tx_gro` remains disabled by default;
the core dataplane and all unrelated ownership, queue, QUIC, DNS, Session-NAT,
and release-provenance behavior remain frozen.

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
current released version:           v1.0.10
v1.0.4 networking/runtime baseline: dcbd06708cf80a0f55bc5a0f0bed8660a26fd655
v1.0.2 historical runtime baseline: 3a07c4be6ad027620cfdaddad13a53609b7c0a06
connect-ip-go:                     57381910bb5fca61b4d3d03fe098929bc294ad11
  pseudo-version:                  v0.0.0-20260905040753-57381910bb5f
quic-go:                           ac11e929d6decc0eb5f8235259ef82671dad3bca
  pseudo-version:                  v0.0.0-20260905040559-ac11e929d6de
```

The main module and connect-ip-go both replace the MetaCubeX quic-go module
with the same Piggy-Cat-bit-shadow fork checkpoint. Do not use `go get -u`.
Any dependency change requires upstream diff review, targeted tests, race,
vet, benchmark comparison, module verification, and a new main pin.

## v1.0.9 final release provenance

The v1.0.9 annotated tag object is `7d495d4590e08503c2b6311ce8c9cdc4dfddf395`
and targets `a5fd3daa773d2a8a69f9738a8dbbf4ef34b2d506`. Tag workflow
`33969687921` passed all build and release gates. The CI artifact and the
published GitHub Release asset are both 8,954,004 bytes with SHA256
`c0037990939410a7c1c7738ee8e88aea5d5fde5a5534d8455a68c156378580fa`;
the checksum, remote asset digest, and byte-for-byte `cmp` all agree.

F-501 is FIXED and RELEASED in v1.0.9. F-502's historical v1.0.8
self-description residual remains immutable; its future recurrence prevention
is FIXED by the tag-only README, maintenance, and release-notes consistency
gate. F-404 remains `REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING`.

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

The release path is:

```text
annotated tag
→ tag-derived version and exact commit
→ GitHub Actions validation gates
→ one static Linux amd64 build
→ workflow artifact with binary, checksum, and RELEASE.txt
→ release job downloads that same artifact
→ checksum, metadata, size, and remote asset verification
→ draft release publication
```

The release job never rebuilds. Local builds are for reproduction/audit only:

```sh
TAG="${TAG:?set an annotated tag such as v1.0.4}"
VERSION="${TAG#v}" COMMIT="$(git rev-list -n1 "$TAG")" \
  scripts/build-release.sh
```

The wrapper requires explicit `VERSION` and full 40-character `COMMIT` values.
It verifies embedded metadata on native Linux, writes `dist/RELEASE.txt`, and
the workflow checks that its SHA256 equals the generated checksum and binary.
Do not include private paths, credentials, hostnames, or deployment identifiers.

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

### v1.0.3 provenance addendum

The v1.0.3 source commit passed repository CI gates, but its CI candidate binary
used embedded version `0.1.0` and was not byte-identical to the separately
built GitHub Release asset. The historical release asset was 8,945,812 bytes
with SHA256
`99a4a495b222640d559e5403b40e089ce5a94afd950729cef07a338b6381cb6d`.
This is a release provenance gap, not a claim that the historical binary was
corrupt. The v1.0.4 candidate workflow closes this gap through tag-derived
metadata and same-artifact release upload; v1.0.3 tags and assets are unchanged.

## v1.0.4 tag-only failed release attempt

The v1.0.4 annotated tag was created successfully, but its release workflow
stopped before tests and build because the local tag-ref validation was
incompatible with `actions/checkout` tag checkout behavior. No GitHub Release
was created, no artifact was manually substituted, and the tag remains
immutable. v1.0.4 is not a released version.

| Finding | Final pre-tag status |
| --- | --- |
| F-401 | FIXED |
| F-402 | FIXED |
| F-403 | FIXED |
| F-404 | REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING |
| F-405 | WORKFLOW BUG CONFIRMED; VALIDATION HOTFIX IN `983e283` |
| F-406 | FIXED |
| H-305 | MEASURE FIRST |
| H-306 | PRODUCTION A/B REQUIRED |

The v1.0.4 release notes contain the intended maintenance scope. The
CONNECT-IP packet dataplane, CONNECT-UDP DATAGRAM path,
PacketPool, owned buffers, queues, retained receive budget, final
serialization copy, GSO, TargetPolicy, DNS Gateway, Session-NAT cleanup
lifecycle, Mihomo performance profile, SNI Router, and fork dependency SHAs
are unchanged. F-404 remains deferred pending real Linux/VPS conntrack
reproduction. The corrected remote-object validator is being carried into the
v1.0.5 release attempt.

The v1.0.5 annotated tag was then created from the first validator-hotfix
candidate, but its workflow stopped before tests/build because the build
metadata step did not receive `GH_TOKEN` for the GitHub API call. No GitHub
Release or substituted artifact was created, and v1.0.5 remains immutable.
The token wiring fix is being carried into the v1.0.6 release attempt.

The v1.0.6 tag reached the release job and completed the full build gates, but
release verification stopped because `actions/download-artifact` restored the
Linux binary without its executable bit. No GitHub Release or substituted
artifact was created, and v1.0.6 remains immutable. The release-job permission
fix is being carried into the v1.0.7 release attempt.

The v1.0.7 build and artifact jobs passed and the workflow created the draft
release, but draft verification used the published-release tag endpoint, which
returns 404 before publication. The draft has not been published and v1.0.7
remains an immutable failed release attempt. The verification query is being
fixed for the v1.0.8 release attempt.

## v1.0.8 final release provenance

The v1.0.8 annotated tag target is
`14ed18241268a07bb462792b348dd27e5c24ce8b`. Tag workflow
`33967069080` passed the full build and release jobs. The workflow artifact and
the published GitHub Release binary are byte-identical:

```text
bytes: 8949908
sha256: f3a50f592b30c69ca14a06be1690a550dcd138a77d966e474bf9ee4ca0cc2d1f
```

The release is [jiejie-masque v1.0.8](https://github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/releases/tag/v1.0.8),
with `draft=false` and `prerelease=false`. Its two formal assets are the Linux
amd64 binary and its checksum file. F-405 is FIXED: CI artifact and GitHub
Release artifact passed `cmp`, size, checksum, embedded metadata, and remote
digest verification. The post-release provenance record is documentation-only
and is not part of the v1.0.8 tag.

| Finding | Final status |
| --- | --- |
| F-401 | FIXED |
| F-402 | FIXED |
| F-403 | FIXED |
| F-404 | REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING |
| F-405 | FIXED |
| F-406 | FIXED |
| H-305 | MEASURE FIRST |
| H-306 | PRODUCTION A/B REQUIRED |

## v1.0.9 release preparation — F-501 only

F-501 is a confirmed conntrack cleanup result-classification bug. A command
that exits non-zero with explicit `0 flow entry`/`0 flow entries` output is a
benign no-op, so cleanup continues from `-s` to `-d`; other command failures
remain errors. Timeout classification now uses the saved context error before
the per-command cancel and only treats `context.DeadlineExceeded` as timeout.
This removes one confirmed source of incomplete cleanup. F-404 remains
`REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING` and still concerns genuine
cleanup failure/restart/reuse behavior, not this fixed result-classification
bug. F-501 is the only runtime change in this release. F-502 adds a tag-only
consistency gate requiring README, maintenance, and release-note versions to
match the tag; the historical v1.0.8 self-description remains immutable.

## v1.0.4 candidate — maintenance batch 1

This candidate reopens only CONNECT-TCP lifecycle handling, CONNECT-IP config
loading, and network-preparation config propagation:

| Finding | Candidate status |
| --- | --- |
| F-401 | FIXED |
| F-402 | FIXED |
| F-403 | FIXED |
| F-404 | REPRODUCTION REQUIRED |
| F-405 | IMPLEMENTED / REAL TAG-PATH VALIDATION PENDING |
| F-406 | FIXED |

CONNECT-TCP now treats directional EOF as half-close: client-to-target EOF
uses TCP `CloseWrite`, target-to-client EOF closes only the HTTP/3 send
direction, and only abnormal copy errors trigger bidirectional teardown.
CONNECT-IP semantic YAML defaults and validation remain solely in
`config.Load`; the mode envelope is routing-only. The network-prepare helper
supports fixed `tunnel-prefix` and `external-interface` field queries while
retaining the legacy no-field tunnel-prefix output and the CLI/env/YAML/route
interface precedence. F-404, release provenance, README drift, H-305, and H-306
are intentionally outside this batch.
