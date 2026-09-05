# jiejie-masque v1.0.1

Maintenance release. This release freezes the current runtime architecture;
future runtime changes require demonstrated correctness, security,
compatibility, ownership, or shutdown evidence.

## Correctness and compatibility

- Mihomo configuration generation derives the client public key from the
  supplied P-256 private key, selects the matching configured client, and uses
  that client's tunnel address. Explicit `--client` selection must agree with
  the private-key identity. SEC1 P-256 DER base64 and PKCS#8 P-256 ECDSA
  private keys are accepted; public keys are canonical uncompressed-point
  base64.
- The CONNECT-IP dependency validates the true IPv4 IHL, preserves IPv4
  options, rejects malformed header lengths, decrements TTL, and recomputes the
  full IPv4 header checksum.
- CONNECT-IP uses an explicit nonblocking HTTP/3 DATAGRAM API for opportunistic
  reads; compatibility fallbacks remain isolated from the production path.
- Terminal close/error handling, queue draining, and owner release remain
  exactly-once operations.

## CONNECT-UDP and CONNECT-TCP

- CONNECT-UDP uses buffer-aware DATAGRAM receive and owned DATAGRAM send paths.
- HTTP/3 `TrackStream` now wires owned forwarding through
  `stateTrackingStream` to the QUIC owned send API.
- CONNECT-UDP target reads use a 1510-byte backing with 8-byte H3 headroom,
  one Context ID byte, and a one-byte oversized sentinel. Normal forwarding
  has zero full payload copies before final QUIC serialization.
- The owned buffer pool is shared at Proxy scope. It is a reusable `sync.Pool`
  cache, not a strict global memory bound; live ownership scales with active
  flows and QUIC send queues.
- Oversized UDP packets are dropped without forwarding truncated prefixes and
  are reported through a 30-second aggregate log window.
- UDP and TCP target establishment uses the request context. Target hostnames
  are resolved once, validated, and never passed to a final dialer. UDP tries
  up to four validated numeric addresses sequentially; TCP races up to four.
- Flow activity uses an atomic mark and reaper timestamp materialization rather
  than `time.Now` on every successful packet or stream write.

## Reliability and operations

- QUIC startup diagnostics report requested/effective UDP socket buffers where
  supported; insufficient tuning is observable and non-fatal.
- Runtime systemd watchdog heartbeat is separated from the host-network deep
  probe. CONNECT-UDP remains `Type=notify` with readiness, watchdog, and
  graceful signal-aware shutdown behavior.
- Operational guidance now documents watchdog scope, deep-probe scope, direct
  UDP backend versus SNI Router validation, and default versus CUBIC testing.

## Explicit non-changes

- The final QUIC `DatagramFrame.Append` serialization copy remains intentional.
- QUIC DATAGRAM queue sizes, retained receive budget, GSO, TUN offload model,
  and ownership contracts are unchanged.
- No sendmmsg/recvmmsg, MSG_ZEROCOPY, io_uring, BBR, custom crypto,
  incremental checksum, or UDP batching implementation is included.
  sendmmsg/recvmmsg are deferred and are not release blockers without Linux
  production profile evidence.
- `v1.0.0` is not moved or overwritten.

## Dependency provenance

```text
connect-ip-go  57381910bb5fca61b4d3d03fe098929bc294ad11
  v0.0.0-20260905040753-57381910bb5f
quic-go        ac11e929d6decc0eb5f8235259ef82671dad3bca
  v0.0.0-20260905040559-ac11e929d6de
```

The main module and connect-ip-go use the same quic-go fork checkpoint.

## Verification

The release gates include formatting, tidy diff, module verification, full
test/race/vet suites, dependency/privacy/systemd/shell checks, static stripped
Linux amd64 build checks, and GitHub Actions CI. The final release commit is
the target of the annotated `v1.0.1` tag.
