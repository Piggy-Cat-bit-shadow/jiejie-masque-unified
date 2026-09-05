# jiejie-masque v1.0.4

Post-v1.0.3 correctness, deployment, and release-provenance maintenance
release.

No CONNECT-IP or CONNECT-UDP dataplane architecture was redesigned.

## Correctness and compatibility

- CONNECT-TCP preserves standard directional half-close semantics. A normal
  client-to-target EOF sends TCP FIN with `CloseWrite` while target-to-client
  traffic remains active. A normal target-to-client EOF gracefully closes only
  the HTTP/3 send direction while the request direction remains usable.
  Abnormal TCP or QUIC stream errors still trigger full teardown. This is a
  protocol compatibility and correctness fix, not a performance optimization.
- CONNECT-IP CLI dispatch no longer performs a raw `Config.Validate()` before
  defaults are applied. `config.Load` is now the single full CONNECT-IP
  semantic YAML path for defaults, `KnownFields`, validation, and
  multiple-document rejection. Omitted `session_nat.max_sessions` and
  `session_nat.reuse_delay` therefore receive their defaults of `120` and
  `30m`.
- `host_network.external_interface` now propagates through the privileged
  network-preparation path without reintroducing shell YAML parsing. The
  precedence is CLI `--interface`, `MASQUE_EXTERNAL_INTERFACE`, YAML
  `host_network.external_interface`, then default-route autodetection.

## Release provenance

Formal releases are now produced from annotated version tags. The tag supplies
the version and exact commit. The build job runs the full repository gates,
builds one Linux amd64 artifact, records its checksum and `RELEASE.txt`
provenance, and uploads it as a workflow artifact. The release job downloads
that exact artifact, does not rebuild, verifies embedded metadata, checksum,
byte size, and the remotely uploaded release asset, and publishes only after
those checks pass.

This closes the v1.0.3 provenance gap where repository CI validated the source
commit but the separately built GitHub Release asset was not the same
byte-identical CI artifact. The historical v1.0.3 asset was not declared
corrupt.

## Documentation and deferred findings

- Repository release/version documentation was aligned with the actual
  released version and tag-driven release process.
- F-404 remains `REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING`; cleanup
  failure state-machine behavior was not changed.
- H-305 remains `MEASURE FIRST`.
- H-306 remains `PRODUCTION A/B REQUIRED`.

## Explicit non-changes

The CONNECT-IP packet dataplane, CONNECT-UDP DATAGRAM dataplane, `PacketPool`,
owned DATAGRAM path, queue sizes, retained receive budget, final serialization
copy, GSO, `TargetPolicy`, DNS Gateway, Session-NAT cleanup lifecycle, Mihomo
performance profile, SNI Router, and fork dependency SHAs are unchanged.

## Dependency provenance

```text
connect-ip-go: 57381910bb5fca61b4d3d03fe098929bc294ad11
pseudo-version: v0.0.0-20260905040753-57381910bb5f
quic-go: ac11e929d6decc0eb5f8235259ef82671dad3bca
pseudo-version: v0.0.0-20260905040559-ac11e929d6de
```
