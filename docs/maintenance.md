# Maintenance and release guide

The v1.0.1 runtime baseline is frozen. Accept correctness, security,
compatibility, ownership, shutdown, and release-metadata fixes. Do not reopen
speculative performance work without reproducible production evidence.

## Exact dependency provenance

```text
main HEAD at release preparation: adcf5f731e5fca8e1ba4d26724ea62b58af57248
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
VERSION=1.0.1 OUTPUT=dist/jiejie-masque-linux-amd64 scripts/build-release.sh
sha256sum dist/jiejie-masque-linux-amd64 > dist/jiejie-masque-linux-amd64.sha256
sha256sum -c dist/jiejie-masque-linux-amd64.sha256
```

Verify x86-64 ELF, static linkage, stripped symbols, exact byte size, and the
embedded version/commit. Upload only the binary and checksum to the GitHub
Release. Do not include private paths, credentials, hostnames, or deployment
identifiers.

## Frozen optimization boundary

Normal CONNECT-IP RX and CONNECT-UDP client-to-target application payload
copies are zero. Normal CONNECT-IP TX and CONNECT-UDP target-to-client paths
have zero full payload copies before final QUIC serialization. The final
`DatagramFrame.Append` copy remains intentional. `sendmmsg`/`recvmmsg`,
MSG_ZEROCOPY, io_uring, public DATAGRAM pooling, custom crypto, incremental
checksum, new congestion controllers, and UDP batching are deferred and are
not release blockers. Reopen them only with Linux production profile,
syscall/CPU/latency, allocation, qlog, or packet-loss evidence.

## Local environment caveats

Constrained local UDP/TLS environments can expose timing failures in upstream-
style quic loopback tests or race-instrumented allocation tests. Confirm the
targeted package, main CI, and release gates before classifying such a failure
as a product defect. This is a validation caveat, not a reason to alter runtime
behavior during a release audit.
