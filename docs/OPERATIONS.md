# Provider operations

This release candidate targets roughly 10–20 trusted users and 20–50 devices on a small Linux VPS. These are starting points, not universal tuning values.

CONNECT-UDP defaults are 256 active flows globally, 64 per user, one-hour flow idle cleanup, a 10-second handshake timeout, 64 incoming streams, 15-second keepalive, and two-minute QUIC idle timeout. CONNECT-IP defaults are 120 sessions globally, 32 per client, one-hour session idle cleanup, 30-minute shadow-address reuse delay, and a bounded 256-packet outbound queue. Queue overflow is logged only as an anonymous aggregate count; a stalled client cannot block the global TUN dispatcher. Per-session queue counters (accepted, dequeued, dropped, high-water) are lock-free and intentionally contain no client identity.

To compare the bounded handoff under reproducible overload, run `go test -run '^$' -bench BenchmarkQueue -benchmem ./internal/connectip/session`. The controlled-drain benchmark offers eight packets for each logical writer dequeue; the burst-recovery benchmark offers 256 packets then fully drains before the next burst. They report allocation cost, drop rate, and queue high-water without scheduler-dependent sleeps. The 256-packet default is the smallest tested depth that absorbs the recovery burst; use production measurements before increasing it.

CONNECT-IP DNS defaults to a TCP+UDP gateway on the server tunnel address and port 5353, forwarding only to the VPS-local `127.0.0.1:53` resolver. Keep AdGuard Home listening on that loopback address. The service neither changes kernel BBR/qdisc/sysctl settings nor exposes DNS on a public address.

Edit users only through `auth.users` and `password_env`; do not store passwords in YAML. Add or remove CONNECT-IP clients through `clients`, using generated public keys. Before every restart, run `jiejie-masque check-config --config PATH`, then use `systemctl restart jiejie-masque-connect-ip` or `systemctl restart jiejie-masque-connect-udp`.

Inspect resource use with `systemctl show SERVICE -p MemoryCurrent -p MemoryPeak -p TasksCurrent`, open listeners with `ss -Huanp`, and file descriptors with `ls /proc/$(systemctl show -p MainPID --value SERVICE)/fd | wc -l`. Confirm the deployed build with `jiejie-masque --version`. Roll back by restoring the previous verified binary and SHA256, checking config, then restarting the affected service.
