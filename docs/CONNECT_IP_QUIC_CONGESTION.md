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

For CONNECT-IP WAN deployments, the project now defaults to `cubic`. The
Reno-compatible `default` mode remains available as an explicit rollback.

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
`github.com/Piggy-Cat-bit-shadow/quic-go` commit
`bc10ff1536061eeabfbb92aae28c4fae35377e7c`.
It is based on canonical quic-go v0.62.0 commit
`793f74d8e03368c5aded128af6f48d21dbb47f73`; the fork
adds the project's DATAGRAM/ownership integration and selected congestion-control
support, plus the
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
back to CUBIC; there is no BBR profile setting in this build. The IETF CCWG
now has an Experimental BBRv3 draft (`draft-ietf-ccwg-bbr-06`, July 2026), but
that does not make an unvalidated QUIC port production-ready. This project
therefore keeps BBR out of the production build until pacing, loss, ECN,
reordering, and WAN regression coverage exist.

## WAN queue / congestion findings

Field observation found a feedback loop: Reno-compatible `default`
plus a 256-packet Session queue reached about 33 Mbps while overflowing the
application queue, while CUBIC plus a 1024-packet Session queue reached about
45 Mbps on the same environment. The fork now uses bounded QUIC DATAGRAM
queues of 512 send / 256 receive and HTTP/3 stream DATAGRAM queue 256.

These are bounded buffers, not an unlimited backlog; the project keeps MTU
1280 and TUN offload/TX GRO disabled by default.

## WAN A/B procedure and queue guidance

Do not use localhost throughput to choose a production controller. Keep MTU
1280, outbound queue 1024, DNS, and client build fixed. On a disposable Linux
test path, use the existing reversible harness in a separate terminal:

```bash
sudo scripts/benchmark-netem.sh eth0 150ms 0.5% 10ms
```

For each `default` and `cubic`, restart only CONNECT-IP after changing
`quic.congestion_controller`, then collect the same short transfer plus 100 MB
and 500 MB downloads from Mihomo. Repeat at 50/100/150/200 ms and 0/0.1/0.5/1%
loss. Record throughput, ramp-up time, loaded/p95 RTT, loss recovery, and CPU.
The harness restores its qdisc when interrupted. No WAN results are fabricated
by this repository. A field observation recorded about 33 Mbps with
`default + queue=256`, frequent Session queue overflow, and about 45 Mbps with
`cubic + queue=1024`. That is evidence for a starting production profile, not a
universal guarantee: use `cubic + 1024` for new WAN deployments, then A/B
against `default + 256`, `cubic + 256`, `cubic + 512`, `cubic + 2048` on the
actual path. Keep the queue bounded; 1024 at MTU 1280 is about 1.25 MiB per
session and 2048 is about 2.5 MiB.

For a repeatable full matrix, use `scripts/benchmark-connect-ip-matrix.sh` with
an operator-provided Mihomo/HTTP download runner. It covers 20/50/100/150/200
ms, 0/0.1/0.5/1% loss, both controllers, and queues 256/512/1024/2048, writing
one CSV row per case. Set `CONFIGURE_CMD` if a disposable deployment needs to
render/restart its server between cases. The runner should report peak and
average Mbps, ramp-up, retransmissions/loss, CPU, memory, and loaded RTT; the
service snapshot supplies queue high-water/drop and TUN counters.

The configuration fallback is now `cubic` and 1024 when fields are omitted;
explicit `default` and 256 remain valid rollback values. The server-side outer
QUIC sender controls download ramp-up; Mihomo's inner BBR settings cannot
replace it.

The service emits an identity-free 30-second dataplane snapshot containing
Session queue depth/high-water/enqueue/dequeue/drop counters, TUN packet/byte
and batch counters, heap allocation and GC count. It logs UDP
`SO_RCVBUF`/`SO_SNDBUF` both before and after `Transport.Listen`; the post-tuning
line is the effective value. The lower QUIC fork's runtime snapshot includes
controller/state, cwnd, inflight, pacing, RTT, loss, reordering, PMTU, GSO and
queue pressure. Aggregation sums additive counters, uses minimum non-zero
PMTU/MinRTT, conservative maximum latest/smoothed RTT, and reports `mixed`
when controller/state differ; it never logs connection identity or payload.
The lower QUIC fork's DATAGRAM send
queue is bounded at 512 send / 256 receive and applies documented backpressure
or bounded drop rather than silently growing;
the Session queue is the intentional drop boundary.
