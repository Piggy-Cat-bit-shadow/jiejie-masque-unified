# Current maintenance and release specification

The current maintenance release is `v1.0.15`.
Current released version: `v1.0.15`

This document describes the current repository contract. It is not a release
ledger and does not preserve superseded release narratives.

## Current dependency provenance

The main module must use the maintained forks below:

```text
current connect-ip-go version: v0.0.0-20260920111434-ff8a7b5f1c62
current quic-go replacement version: v0.61.1-0.20260920111406-607c23f0eaf0
```

The replacement must remain explicit in `go.mod`. Run both
`scripts/verify-deps.sh` and `scripts/verify-dependency-provenance.sh` after
every dependency change. Dependency updates are accepted only with a pinned
commit, reproducible `go.sum`, upstream/license review, and the complete test
and race gates.

## Runtime invariants

- Production congestion control is CUBIC.
- QUIC DATAGRAM queues are bounded at send 512 and receive 256.
- HTTP/3 stream DATAGRAM queue is bounded at 256.
- CONNECT-IP outbound queue defaults to 1024 and retained receive budget is 64.
- CONNECT-UDP payload admission is bounded to 1500 bytes.
- Flow, session, NAT cleanup and packet ownership have explicit shutdown paths;
  every owned packet is released exactly once.
- IPv6 tunnel MTU is at least 1280. IPv6 `::/0` is advertised only when the
  operator explicitly enables it for a routed public IPv6 prefix.
- TUN offload and TCP TX GRO remain disabled by default.
- qlog is opt-in, identity-free, written with mode 0600, and its directory is
  validated before service startup.

## Required local gates

Before commit or release, run:

```sh
test -z "$(gofmt -l .)"
go mod tidy -diff
go mod verify
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Also run the repository contracts:

```sh
bash scripts/verify-deps.sh
bash scripts/verify-dependency-provenance.sh
bash scripts/verify-public-repo.sh
bash scripts/verify-systemd-contract.sh
bash scripts/test-connect-ip-network-prepare.sh
bash scripts/verify-workflow-contract.sh
bash scripts/verify-release-docs-selftest.sh
bash scripts/verify-release-tag-selftest.sh
bash scripts/verify-dependency-provenance-selftest.sh
bash scripts/verify-git-metadata-selftest.sh
bash scripts/verify-public-repo-selftest.sh
bash scripts/verify-release-docs.sh v1.0.15 .
```

Linux CI additionally runs dataplane benchmarks, TX GRO and ICMP/fragment
stress, Linux amd64 build checks, systemd verification and release binary
metadata checks. Synthetic netem tests are regression tools only; they do not
replace a real VPS WAN, high-RTT, mobile or reordered-path evaluation.

## Release procedure

1. Keep the worktree clean except for the intended release changes and review
   tracked, deleted and untracked files for credentials, private keys, build
   output and production configuration.
   New commits must use the repository's GitHub noreply identity so future
   metadata privacy checks do not expose a personal email address.
2. Run all local gates and push `codex/unified-masque` without force push.
3. Wait for the branch workflow to finish successfully.
4. Create an annotated semver tag whose target is the exact validated commit:

   ```sh
   git tag -a v1.0.15 -m "jiejie-masque v1.0.15"
   git push origin v1.0.15
   ```

5. The tag workflow validates the tag object, current README and maintenance
   markers, current release note, embedded version/commit, SHA256, size,
   remote digest and downloaded artifact bytes. It builds once and releases
   the same artifact.
6. Verify the GitHub release is published, non-draft and non-prerelease, and
   verify the downloaded binary with `--version` and its checksum.

The only release note maintained by the repository is
`docs/RELEASE_NOTES_v1.0.15.md`. A future release replaces the current marker
and current release note as one intentional consolidation change; the Git
commit graph is never rewritten.

## Operations and ownership requirements

Configuration files and environment files use mode 0600. Service directories
use mode 0700. Private keys remain outside Git. `check-config` must pass before
restart, and `doctor` plus network prepare must pass before the first host
deployment. systemd units must retain their notify/watchdog and capability
contracts.

When changing a queue or buffer, document its producer, consumer, close
behavior, drop policy, high-water metric and ownership transfer. Do not raise a
default solely to hide backpressure. Performance claims require clean-path
control plus real WAN measurements covering goodput, loaded RTT, CPU, RSS,
syscalls, packet loss, reordering and queue pressure.

## Known limitations

Public IPv6 egress depends on the deployment provider routing the configured
prefix; a tunnel address alone does not prove Internet reachability. Session
NAT is IPv4-only. Offload, PMTU ceilings and experimental congestion control
remain opt-in until measured on representative paths. Release CI cannot prove
firewall policy or provider routing on an individual VPS.
