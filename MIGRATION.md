# Migration

Install one binary and run each mode as its own service with `/etc/jiejie-masque/connect-ip.yaml` or `/etc/jiejie-masque/connect-udp.yaml`.

For CONNECT-IP, copy the existing P-256 `server.crt` and `server.key` byte-for-byte to the new paths. Do not regenerate them: Mihomo pins the server public key. Copy the existing CONNECT-IP reset key from `/var/lib/masque-lite/stateless-reset.key` to `/var/lib/jiejie-masque-connect-ip/stateless-reset.key`, and preserve the existing CONNECT-UDP reset key when moving its state directory.

This repository does not modify production VPS configuration, SNI routing, or either legacy repository.
