# jiejie-masque v1.0.2

Maintenance correctness and security release.

The v1.0.2 runtime baseline is
`3a07c4be6ad027620cfdaddad13a53609b7c0a06`. This release does not introduce
speculative dataplane performance redesign.

## Mihomo compatibility

- Server endpoint `public-key` output is canonical PKIX/
  SubjectPublicKeyInfo DER Base64 for Mihomo's `x509.ParsePKIXPublicKey`
  consumer contract.
- Client `private-key` input accepts SEC1 and PKCS#8 P-256 DER Base64 and emits
  canonical SEC1 P-256 DER Base64 for `x509.ParseECPrivateKey`.
- Client authentication public keys remain raw uncompressed P-256 points.
- Consumer-contract tests cover parser compatibility, canonicalization,
  negative raw-point handling, and key identity preservation.

## DNS and configuration correctness

- CONNECT-IP DNS requests use a 4097-byte sentinel buffer: requests up to
  4096 bytes are valid, while oversized requests are dropped without
  forwarding a truncated prefix.
- Configured client names are unique and effective identities are deterministic;
  two unnamed clients remain valid.
- Negative `max_sessions_per_client` and `reuse_delay` values are rejected.
- Network preparation obtains the tunnel CIDR through the binary's
  `network-prepare-info` command and the single YAML parser with strict field
  validation.
- Repository-wide privacy checks cover tracked private-key encodings and public
  domains/addresses without falsely classifying PKIX public keys as secrets.

## Target security policy

- With `allow_private: false`, CONNECT-UDP and CONNECT-TCP allow only public,
  globally reachable unicast targets according to IANA special-purpose registry
  semantics, including more-specific globally reachable exceptions.
- IPv4-mapped IPv6 addresses are unmapped before classification.
- Hostnames are resolved once, every result is validated, and only validated
  numeric addresses are dialed.
- `target_policy.connect_timeout` is one overall DNS-plus-establishment
  deadline and defaults to 10 seconds; parent cancellation remains authoritative.

## Session-NAT lifecycle

- A shadow IP remains unavailable while cleanup for its previous generation is
  pending, preventing reuse-before-conntrack-cleanup races.
- Cleanup runs on two fixed workers with a queue bounded by `max_sessions`.
  Normal queue-full operation applies backpressure without holding the Manager
  lock or silently dropping work.
- `reuse_delay` starts after the cleanup attempt completes, including errors.
  Errors are observable and do not terminate workers.
- Shutdown waits for running cleanup and may discard queued cleanup work; it
  does not perform an unbounded drain.

## Tooling and privacy

The release gates retain formatting, module verification, tests, race, vet,
dependency, privacy, systemd, and shell validation. No private configuration,
test key, real deployment address, or production credential is part of the
release artifacts.

## Performance and architecture status

Normal application data paths retain zero full-payload copies before final
QUIC serialization. The final serialization copy remains intentional. The
retained receive budget is 64; queue and buffer constants remain frozen.
Synthetic Manager churn does not justify a lock architecture redesign:
`MANAGER LOCK REFACTOR NOT JUSTIFIED`.

Deferred work includes sendmmsg/recvmmsg, MSG_ZEROCOPY, io_uring, public
DatagramBuffer pooling, final serialization-copy removal, custom crypto,
incremental checksum work, new congestion controllers, queue-age
instrumentation, and target-side UDP batching.

## Dependency provenance

- connect-ip-go: `57381910bb5fca61b4d3d03fe098929bc294ad11`
  (`v0.0.0-20260905040753-57381910bb5f`)
- quic-go: `ac11e929d6decc0eb5f8235259ef82671dad3bca`
  (`v0.0.0-20260905040559-ac11e929d6de`)

## Verification

The final release commit is validated by the repository's full test, race,
vet, module, dependency, privacy, systemd, shell, and Linux amd64 release
gates. See `docs/maintenance.md` and `docs/OPERATIONS.md` for the complete
maintenance and operational procedures.

## Explicit non-changes

This release does not change the CONNECT-IP or CONNECT-UDP packet dataplane,
QUIC fork, dependency pins, production deployment, or historical release tags.
