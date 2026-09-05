# jiejie-masque v1.0.6

Post-v1.0.3 correctness, deployment, and release-provenance maintenance
release.

No CONNECT-IP or CONNECT-UDP dataplane architecture was redesigned.

## Included maintenance fixes

- F-401: CONNECT-TCP preserves directional half-close semantics. Normal EOF
  uses the appropriate half-close direction; abnormal TCP or QUIC errors still
  trigger full teardown.
- F-402: CONNECT-IP configuration loading applies defaults, `KnownFields`,
  validation, and multiple-document rejection through the single semantic
  YAML loader.
- F-403: `host_network.external_interface` propagates through privileged
  network preparation with CLI, environment, YAML, and route-detection
  precedence preserved.
- F-405: release validation verifies the remote GitHub annotated tag object,
  exact commit target, and checked-out `GITHUB_SHA`. Both workflow jobs pass
  the required GitHub token to the remote validator, and release assets still
  come from one validated workflow artifact without rebuilding.
- F-406: release/version documentation remains aligned with the tag-driven
  release process.

v1.0.4, v1.0.5, and v1.0.6 were not released. Their annotated tags remain
immutable, tag-only failed release-attempt markers; no GitHub Release or
substituted artifact was created for any of these tags. The v1.0.6 build gates
passed, but release verification found that artifact download did not preserve
the Linux binary executable bit; the release job now restores it explicitly.

## Deferred finding

F-404 remains `REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING`. H-305 remains
`MEASURE FIRST`, and H-306 remains `PRODUCTION A/B REQUIRED`.

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
