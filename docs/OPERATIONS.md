# Provider operations

This release candidate targets roughly 10–20 trusted users and 20–50 devices on a small Linux VPS. These are starting points, not universal tuning values.

CONNECT-UDP defaults are 256 active flows globally, 64 per user, one-hour flow idle cleanup, a 10-second handshake timeout, 64 incoming streams, 15-second keepalive, and two-minute QUIC idle timeout. CONNECT-IP defaults are 120 sessions globally, 32 per client, one-hour session idle cleanup, 30-minute shadow-address reuse delay, and a 512-packet outbound queue.

Edit users only through `auth.users` and `password_env`; do not store passwords in YAML. Add or remove CONNECT-IP clients through `clients`, using generated public keys. Before every restart, run `jiejie-masque check-config --config PATH`, then use `systemctl restart jiejie-masque-connect-ip` or `systemctl restart jiejie-masque-connect-udp`.

Inspect resource use with `systemctl show SERVICE -p MemoryCurrent -p MemoryPeak -p TasksCurrent`, open listeners with `ss -Huanp`, and file descriptors with `ls /proc/$(systemctl show -p MainPID --value SERVICE)/fd | wc -l`. Confirm the deployed build with `jiejie-masque --version`. Roll back by restoring the previous verified binary and SHA256, checking config, then restarting the affected service.
