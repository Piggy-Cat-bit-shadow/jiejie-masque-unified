# jiejie-masque v1.0.8

Post-v1.0.3 correctness, deployment, and release-provenance maintenance
release.

No CONNECT-IP or CONNECT-UDP dataplane architecture was redesigned.

## Included maintenance fixes

- F-401: CONNECT-TCP preserves directional half-close semantics.
- F-402: CONNECT-IP configuration loading applies semantic defaults and
  validation through the single YAML loader.
- F-403: `host_network.external_interface` propagates through privileged
  network preparation with the documented precedence.
- F-405: release validation verifies the remote annotated tag object, exact
  commit target, authenticated GitHub API access, executable permissions after
  artifact download, and draft assets through the draft-safe release query.
  Release assets still come from one validated workflow artifact without
  rebuilding.
- F-406: release/version documentation remains aligned with the tag-driven
  release process.

v1.0.4 through v1.0.7 were not formally released. Their annotated tags remain
immutable failed release-attempt markers; no local artifact was substituted.

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
