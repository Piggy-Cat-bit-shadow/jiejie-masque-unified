# jiejie-masque

Unified single-binary MASQUE server with two independent modes:

- `connect-ip`: MetaCubeX CONNECT-IP, P-256 mTLS authentication, Linux TUN, session NAT, watchdog and host-network supervision.
- `connect-udp`: RFC 9298 CONNECT-UDP and HTTP/3 TCP CONNECT (implementation staged separately; see repository status).

Build:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o dist/jiejie-masque-linux-amd64 ./cmd/jiejie-masque
```

Run or validate:

```sh
jiejie-masque serve --config /etc/jiejie-masque/connect-ip.yaml
jiejie-masque check-config --config /etc/jiejie-masque/connect-ip.yaml
```

The modes use separate YAML files, listeners, reset-key paths and systemd services. CONNECT-UDP must not receive `CAP_NET_ADMIN`; CONNECT-IP retains it for TUN and host networking. Production migration is out of scope. Preserve the existing CONNECT-IP P-256 certificate/private key because clients pin its public key.
