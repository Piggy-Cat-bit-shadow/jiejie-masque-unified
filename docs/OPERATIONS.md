# Provider operations

## Runtime health and diagnostics

At startup, the QUIC fork reports requested and effective UDP receive/send
socket buffers when the platform exposes those values. A lower effective value
is a warning and does not by itself prevent startup. Inspect service logs for
the requested/effective pair before changing host limits.

The systemd watchdog and host-network probe have different scopes. The
watchdog uses `WATCHDOG_USEC / 2` and only proves that the service can schedule
and send a systemd heartbeat. It does not prove that the QUIC event loop,
dataplane forwarding, or the remote Internet is healthy. The deep probe runs at
the configured 30-second interval and checks forwarding, TUN, and nft/NAT
conditions; two consecutive failures are required before it becomes fatal.

Both services use `Type=notify`, `WatchdogSec=30s`, and graceful,
signal-aware `ServeContext` shutdown. CONNECT-UDP uses `NotifyAccess=main`.
Readiness is sent only after the listener, QUIC transport, and HTTP/3 server
are constructed. Do not treat READY or WATCHDOG as a packet-forwarding SLA.

## Deployment validation experiments

If production uses a UDP SNI Router, compare a direct UDP backend with the
router path using the same client, target, payload, and duration. This is a
deployment variable to validate, not a known repository bottleneck. Similarly,
compare the supported `default` congestion controller with explicit `cubic`
only under a controlled, reversible test. The repository does not change the
default based on theory or an isolated benchmark.

The current release explicitly defers sendmmsg/recvmmsg and UDP batching. A
future investigation must provide Linux syscall count, CPU, burst, and latency
evidence without waiting for future packets or changing ownership semantics.

This release candidate targets roughly 10–20 trusted users and 20–50 devices on a small Linux VPS. These are starting points, not universal tuning values.

CONNECT-UDP defaults are 256 active flows globally, 64 per user, one-hour flow idle cleanup, a 10-second handshake timeout, 64 incoming streams, 15-second keepalive, and two-minute QUIC idle timeout. CONNECT-IP defaults are 120 sessions globally, 32 per client, one-hour session idle cleanup, 30-minute shadow-address reuse delay, a 30-second host-network deep-probe interval, and a bounded 256-packet outbound queue. The systemd watchdog is a lightweight runtime heartbeat and is independent of the deep probe; it does not claim to detect arbitrary QUIC or datapath deadlocks. Queue overflow is logged only as an anonymous aggregate count; a stalled client cannot block the global TUN dispatcher. Per-session queue counters (accepted, dequeued, dropped, high-water) are lock-free and intentionally contain no client identity.

CONNECT-UDP and CONNECT-TCP target policy defaults to public, globally
reachable unicast destinations only. DNS answers are resolved once, filtered
before dialing, and only validated numeric addresses are passed to the dialer.
Private, local, documentation, benchmarking, CGNAT, and other non-global
special-purpose ranges are rejected unless `target_policy.allow_private: true`
is explicitly enabled. That opt-in permits private/local server-visible
networks, including loopback, LAN, link-local, CGNAT, and ULA destinations;
unspecified, multicast, broadcast, reserved, discard-only, and dummy address
categories remain rejected. `target_policy.connect_timeout` is the overall
DNS-resolution plus validated-target-dial establishment deadline and defaults
to 10 seconds; it is not a flow idle or relay lifetime timeout.

Enabling `target_policy.allow_private` is a deliberate security relaxation for
trusted deployments and can expose private or local server-visible networks.
For CONNECT-IP session NAT, a removed shadow address remains unavailable while
its conntrack cleanup is pending. Cleanup uses a bounded two-worker executor;
only after the cleanup attempt completes does `reuse_delay` begin, including
when cleanup reports an error. Service shutdown waits for running cleanup and
may discard queued cleanup work.

To compare the bounded handoff under reproducible overload, run `go test -run '^$' -bench BenchmarkQueue -benchmem ./internal/connectip/session`. The controlled-drain benchmark offers eight packets for each logical writer dequeue; the burst-recovery benchmark offers 256 packets then fully drains before the next burst. They report allocation cost, drop rate, and queue high-water without scheduler-dependent sleeps. The 256-packet default is the smallest tested depth that absorbs the recovery burst; use production measurements before increasing it.

CONNECT-IP DNS defaults to a TCP+UDP gateway on the server tunnel address and port 5353, forwarding only to the VPS-local `127.0.0.1:53` resolver. Keep AdGuard Home listening on that loopback address. The service neither changes kernel BBR/qdisc/sysctl settings nor exposes DNS on a public address.

Edit users only through `auth.users` and `password_env`; do not store passwords in YAML. Add or remove CONNECT-IP clients through `clients`, using generated public keys. Before every restart, run `jiejie-masque check-config --config PATH`, then use `systemctl restart jiejie-masque-connect-ip` or `systemctl restart jiejie-masque-connect-udp`.

Inspect resource use with `systemctl show SERVICE -p MemoryCurrent -p MemoryPeak -p TasksCurrent`, open listeners with `ss -Huanp`, and file descriptors with `ls /proc/$(systemctl show -p MainPID --value SERVICE)/fd | wc -l`. Confirm the deployed build with `jiejie-masque --version`. Roll back by restoring the previous verified binary and SHA256, checking config, then restarting the affected service.
