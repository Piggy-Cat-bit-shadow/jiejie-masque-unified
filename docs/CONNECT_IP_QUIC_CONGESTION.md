# CONNECT-IP QUIC congestion control

`quic.congestion_controller: default` preserves the behavior of the pinned
MetaCubeX QUIC source exactly. At commit `2548683b76f4`,
`internal/ackhandler.NewSentPacketHandler` calls
`internal/congestion.NewCubicSender(..., true, ...)`: this is the native
CUBIC sender running its Reno-compatible avoidance mode, not BBR.

`quic.congestion_controller: cubic` is an explicit opt-in to the same native
MetaCubeX CUBIC sender with `reno=false`. The server applies it once from the
HTTP/3 `ConnContext` callback, after QUIC accept and before HTTP/3 opens its
control stream or accepts CONNECT-IP request/data streams. It is never changed
per packet. `default` performs no setter call and is the rollback path.

```
QUIC connection accepted
        |
        v
CONNECT-IP CC selector (once, ConnContext)
        |
        +-- default -> pinned MetaCubeX behavior (CUBIC sender, Reno mode)
        |
        +-- cubic   -> pinned MetaCubeX native CUBIC sender
        |
        v
HTTP/3 control stream and CONNECT-IP data plane
```

## Fork provenance

`github.com/metacubex/quic-go` is replaced by
`github.com/Piggy-Cat-bit-shadow/quic-go` commit `a0f328dde1d9`.
It is based on the pinned MetaCubeX upstream commit `2548683b76f4`; the fork
adds `Conn.SetCubicCongestionControl` and its narrow internal bridge, plus the
bounded DATAGRAM ownership, retained receive-buffer, and reusable borrowed
parser paths used by this project. It does not change HTTP/3 wire behavior,
ECN, GSO, PMTU, or loss-recovery policy. Both upstream and fork are MIT
licensed.

## BBR status

BBR is deliberately not exposed in this MIT project build. The current
MetaCubeX Mihomo source at `26c635f69bbe` selects its BBR implementation from
`transport/tuic/congestion_v2` (`NewBbrSender`); that repository's `LICENSE`
is GPL-3.0. The BBR-v1 source header identifies Google quiche commit
`66dea072431f94095dfc3dd2743cb94ef365f7ef`; BBR-v2 identifies Google quiche
commit `e7872fc9e12bb1d46a118949c3d4da36de58aa44`. Copying the resulting
MetaCubeX GPL package into this MIT distribution is therefore not an acceptable
route.

The other located candidate, `tdragoun/quic-go` branch `bbr_v1`
(`a07eb48492755adb24d4f278a92f5e054f1eccad`), is an MIT-licensed proof of
concept against an older, incompatible quic-go API. It requires porting its
private congestion package and lifecycle wiring, so it is neither a maintained
drop-in dependency nor a permissible "minimal native factory" patch. It is not
included. `bbr` fails config validation explicitly rather than silently falling
back to CUBIC; there is no BBR profile setting in this build.

## WAN A/B procedure

Do not use localhost throughput to choose a production controller. Keep MTU
1280, outbound queue 256, DNS, and client build fixed. On a disposable Linux
test path, use the existing reversible harness in a separate terminal:

```bash
sudo scripts/benchmark-netem.sh eth0 150ms 0.5% 10ms
```

For each `default` and `cubic`, restart only CONNECT-IP after changing
`quic.congestion_controller`, then collect the same short transfer plus 100 MB
and 500 MB downloads from Mihomo. Repeat at 50/100/150/200 ms and 0/0.1/0.5/1%
loss. Record throughput, ramp-up time, loaded/p95 RTT, loss recovery, and CPU.
The harness restores its qdisc when interrupted. No WAN results are fabricated
by this repository; until equivalent measurements exist, the production
recommendation is `default`.
