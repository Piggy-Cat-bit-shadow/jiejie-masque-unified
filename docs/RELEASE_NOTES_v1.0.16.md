# jiejie-masque v1.0.16

v1.0.16 is a maintenance release for real-VPS CONNECT-IP deployment correctness
and server-side QUIC diagnostics. Production defaults remain CUBIC, MTU 1280,
outbound queue 1024, DATAGRAM queues 512/256, and TUN offload disabled.

## Fixes

- CONNECT-IP systemd now grants `CAP_NET_BIND_SERVICE` alongside the existing
  TUN capability so an unprivileged `masque-lite` service can bind UDP 443.
  CONNECT-UDP remains without `CAP_NET_ADMIN`.
- The maintained quic-go fork exposes identity-free `RuntimeStats()` from
  server-side HTTP/3 streams. connect-ip-go forwards it when available and
  retains a zero-value fallback for custom stream implementations.
- Socket diagnostics now distinguish pre-tuning values from the effective
  post-`Transport.Listen` values.
- Aggregate diagnostics report controller/state and use explicit multi-connection
  semantics for additive counters, RTTs, PMTU, and mixed controller states.

## Maintained dependency pins

```text
connect-ip-go: v0.0.0-20260920121826-9ff1656afbaf
quic-go replacement: v0.61.1-0.20260920121748-02ac8e5cb125
```

This release does not add BBR/BBRv3, enlarge queues, or change the MTU default.
