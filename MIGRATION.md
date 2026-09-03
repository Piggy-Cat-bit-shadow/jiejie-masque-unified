# Migration

Install one binary and run each mode as its own service with `/etc/jiejie-masque/connect-ip.yaml` or `/etc/jiejie-masque/connect-udp.yaml`.

For CONNECT-IP, copy the existing P-256 `server.crt` and `server.key` byte-for-byte to the new paths. Do not regenerate them: Mihomo pins the server public key. Copy the existing CONNECT-IP reset key from `/var/lib/masque-lite/stateless-reset.key` to `/var/lib/jiejie-masque-connect-ip/stateless-reset.key`, and preserve the existing CONNECT-UDP reset key when moving its state directory.

This repository does not modify production VPS configuration, SNI routing, or either legacy repository.

For CONNECT-UDP, configure users in YAML and provide each `password_env` through `/etc/jiejie-masque/connect-udp.env`; missing configured environment variables must fail startup. Recommended small-provider limits are 256 total active flows and 64 per user. Runtime inspection can use `systemctl show jiejie-masque-connect-udp -p MemoryCurrent -p MemoryPeak -p TasksCurrent` and `ss -Huanp`.
