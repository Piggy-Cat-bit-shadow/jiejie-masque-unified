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
        +-- bbr     -> experimental BBRv1 (explicit opt-in only)
        |
        v
HTTP/3 control stream and CONNECT-IP data plane
```

## Fork provenance

`github.com/metacubex/quic-go` is replaced by
`github.com/Piggy-Cat-bit-shadow/quic-go` commit
`bc10ff1536061eeabfbb92aae28c4fae35377e7c`.
The maintained fork is pinned at `655218e5a1721b50432866cd8a988077b8bd0bac`.
It is based on canonical quic-go v0.62.0 commit
`793f74d8e03368c5aded128af6f48d21dbb47f73`; the fork adds the project's
DATAGRAM/ownership integration, CUBIC and experimental BBRv1 selection, and
bounded DATAGRAM ownership, retained receive-buffer, and reusable borrowed
parser paths. BBR changes its per-connection congestion and pacing model only;
it does not alter HTTP/3 wire behavior or QUIC loss-recovery policy. Both
upstream and fork are MIT licensed.

## Experimental BBRv1 status

`quic.congestion_controller: bbr` explicitly selects an experimental BBRv1
sender for that connection. It is opt-in only; the production default remains
`cubic`, with no automatic switching or fallback. This is a test candidate,
not a claim that BBR is faster or production-ready. CUBIC and BBR real-WAN A/B
results are still required before considering a default change.

The implementation is a selective port/adaptation of
`tdragoun/quic-go:bbr_v1` at
`a07eb48492755adb24d4f278a92f5e054f1eccad`, licensed MIT. Its algorithm
semantics were checked against Google QUICHE commit
`66dea072431f94095dfc3dd2743cb94ef365f7ef` (`bbr_sender.cc`). The BBR source
files retain explicit upstream/source attribution. No source was copied from
MetaCubeX/Mihomo GPL congestion code. QUICHE is a semantic reference; this is
not a direct C++ source translation.

The port deliberately does not copy the PoC's `false &&` / `true ||` constant
expressions. The former represented an optional app-limited-recovery branch
disabled by default at the referenced QUICHE revision. The latter represented
the default-off `quic_bbr_no_bytes_acked_in_startup_recovery` flag, so the
effective default still permits ACK growth during STARTUP recovery. The
recovery boundary was also corrected so ordinary ACKs do not keep moving it to
the latest sent packet. QUIC loss detection, PTO, ECN validation, and packet
reordering remain owned by quic-go; BBR consumes the resulting events only.

BBR uses the same per-connection RTTStats object as loss detection, tracks only
1-RTT packet-number state (the packet number spaces reuse numbers), and is
recreated as BBR after path migration so its bandwidth/RTT model resets for the
new path. It uses the shared pacer with its own gain-adjusted BBR rate (without
CUBIC's additional 1.25 pacing factor). Runtime snapshots expose BBR mode,
bandwidth estimate in bit/s, min RTT, gains, target CWND, round, full-bandwidth,
recovery, and app-limited gauges. For multiple BBR connections, bandwidth and
target CWND are summed, min RTT is the minimum non-zero value, round is the
maximum, and mixed mode/recovery/gain states are labeled accordingly (mixed
gains are reported as unavailable/zero).

The implementation has unit, lifecycle, and deterministic synthetic WAN and
two-flow fairness coverage. The local simulator is not a substitute for real
high-RTT/mobile/reordered-path VPS A/B. Do not infer real-world throughput or
bufferbloat behavior from these tests; keep CUBIC as production default.

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

For each `default`, `cubic`, and experimental `bbr`, restart only CONNECT-IP after changing
`quic.congestion_controller`, then collect the same short transfer plus 100 MB
and 500 MB downloads from Mihomo. Repeat at 50/100/150/200 ms and 0/0.1/0.5/1%
loss. Record throughput, ramp-up time, loaded/p95 RTT, loss recovery, and CPU.
The harness restores its qdisc when interrupted. No WAN results are fabricated
by this repository. A field observation recorded about 33 Mbps with
`default + queue=256`, frequent Session queue overflow, and about 45 Mbps with
`cubic + queue=1024`. That is evidence for a starting production profile, not a
universal guarantee: use `cubic + 1024` for new WAN deployments, then A/B
against `default + 256`, `cubic + 256`, `cubic + 512`, `cubic + 2048`, and
experimental `bbr + 1024` on the
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
