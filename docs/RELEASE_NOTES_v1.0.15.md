# jiejie-masque v1.0.15

## Highlights

v1.0.15 is the current production-candidate release of the unified Linux
MASQUE server. It consolidates the current correctness, dual-stack,
observability, resource-boundary and release-verification contracts.

## CONNECT-IP

- IPv4-only, IPv6-only and dual-stack tunnel addressing is supported.
- Client names are canonicalized once and remain stable in aggregate metrics.
- IPv6 tunnel MTU validation requires at least 1280 bytes.
- Doctor and supervisor checks cover every configured tunnel prefix and report
  family-specific failures.
- Linux default-interface discovery uses the IPv4 default route and falls back
  to the IPv6 default route.
- IPv6 `::/0` advertisement is opt-in and rejects private/ULA prefixes.
- Mihomo output emits only valid configured address families and brackets IPv6
  DNS endpoints correctly.

## CONNECT-UDP / CONNECT-TCP

- Target ports are validated as integers in the inclusive range 1–65535 before
  DNS resolution or dialing.
- Public-destination policy, single-resolution dialing and TCP half-close
  behavior remain enforced.
- HTTP/3 streamer contracts are checked instead of relying on unchecked type
  assertions.
- Per-capsule logging is absent; failures use bounded aggregate diagnostics.

## IPv4 / IPv6

IPv6 public egress is not inferred from tunnel connectivity. Operators must
explicitly enable `advertise_ipv6_default_route` only when the configured
public prefix is routed by the VPS provider. NAT66 and fabricated PREF64 are
not used as substitutes for upstream IPv6 routing.

## Performance and resource boundaries

Production defaults remain CUBIC, QUIC DATAGRAM send/receive queues 512/256,
HTTP/3 stream DATAGRAM queue 256, CONNECT-IP outbound queue 1024, retained
receive budget 64, `tun_offload: false`, and `tun_tx_gro: false`. Runtime
diagnostics expose bounded, identity-free congestion, RTT, loss, reordering,
queue, PMTU and GSO information. QLOG remains opt-in.

## Reliability and security

- qlog directories are validated at startup; qlog files use mode 0600.
- systemd provisions a private LogsDirectory for qlog output.
- Flow reaping retains atomic activity marking, re-checks pending activity and
  closes resources exactly once.
- Configuration, public-repository privacy and dependency provenance gates are
  part of the release workflow.

## Operations

Use `check-config`, `doctor` and the CONNECT-IP network-prepare helper before
the first VPS deployment. Review TUN `INPUT` and `FORWARD` firewall rules,
forwarding, NAT, DNS upstream reachability and provider IPv6 routing. See
`docs/OPERATIONS.md` and `docs/maintenance.md`.

## Dependency provenance

The release uses the maintained fork pins recorded in `docs/FORKS.md` and
`docs/maintenance.md`:

```text
connect-ip-go: v0.0.0-20260920111434-ff8a7b5f1c62
quic-go replacement: v0.61.1-0.20260920111406-607c23f0eaf0
```

## Verification

The release workflow runs formatting, module verification, unit tests, race
tests, vet, dataplane benchmarks, targeted TX GRO and ICMP/fragment stress,
dependency and privacy gates, systemd/network-prepare contracts, Linux amd64
build checks, and same-artifact SHA256/size/remote-digest verification.

## Known limitations

Real high-RTT WAN, mobile and reordered-path measurements are deployment
validation work and are not replaced by loopback or deterministic netem tests.
IPv6 egress depends on provider routing. Experimental congestion control,
offload and PMTU ceiling changes remain opt-in until representative benchmarks
show a safe benefit.
