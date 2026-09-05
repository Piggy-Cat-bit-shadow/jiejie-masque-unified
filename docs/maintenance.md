# Maintenance Guide

The v1 runtime is frozen. Maintenance accepts bug fixes, security fixes,
compatibility fixes, and release metadata corrections. Do not add speculative
performance tuning, architecture rewrites, or new zero-copy experiments.

## Frozen dependency graph

The release candidate pins these self-maintained forks:

```text
main            c94b448f4497f5308cf128efa3e1c5f0b515a068
connect-ip-go   9121aa8beb9b7603dba9ba081c042e386414d809
quic-go         a0f328dde1d9f3d9028e345209fdf74dd9cac3c6
```

Never use `go get -u`. An upstream or fork update requires upstream diff
review, fork rebase/merge, targeted tests, race tests, benchmarks, and a main
module pin update.

## Required checks by change area

Before changing the quic-go fork, run the modified wire, DATAGRAM, HTTP/3,
packet-buffer, and send-queue tests, followed by `go test -race` for those
packages and the quic full suite when the local environment supports it.

Before changing connect-ip-go, run its full test, race, and vet suites. For
ownership changes, cover queue-full drop, close drain, send rejection,
`DatagramTooLargeError`, duplicate Release, and exactly-once owner transfer.

Before changing the main PacketPool or session handoff, verify headroom 9,
the one-byte TUN sentinel, queue overflow release, connection close drain,
direct-read ownership, and pool generation rules. Never reset `refCount` or a
release flag on an object already returned to `sync.Pool`.

Before changing the receive parser, preserve reusable scratch behavior and the
zero-allocation parser benchmark. Verify malformed frames, multiple DATAGRAMs
sharing one packet backing, owner transfer, retained budget 64, and the 65th
compact fallback.

Before changing send serialization, preserve the intentional final copy. Do
not reopen that optimization boundary without profile evidence demonstrating a
material production benefit and a complete AEAD/GSO/lifetime design.

## Release gates

From the final release commit, run:

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

Also build the stripped static Linux amd64 artifact with
`scripts/build-release.sh`, verify ELF/x86-64/stripped properties, generate a
SHA256 file, and validate the Git tag and GitHub Release artifacts.

## Local test-environment caveats

Some upstream-style quic loopback tests can fail on a constrained local UDP
environment: `TestDial/{Dial,DialEarly,DialAddr,DialAddrEarly}` can time out,
`TestTransportAndDialConcurrentClose` uses an intentionally empty TLS config,
and `TestFrameParserAllocs/STREAM` can count race instrumentation allocations.
Under repeated local connect-ip load, `TestClientWaitForSettings` can also hit
its deadline. These are not release highlights; confirm the relevant targeted
tests, the main CI race gate, and the release gates before classifying a
failure as a product defect.
