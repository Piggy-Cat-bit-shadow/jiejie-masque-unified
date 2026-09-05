# jiejie-masque

Unified single-binary MASQUE server with two independent modes:

- `connect-ip`: MetaCubeX CONNECT-IP, P-256 mTLS authentication, Linux TUN, session NAT, watchdog and host-network supervision.
- `connect-udp`: RFC 9298 CONNECT-UDP, HTTP Datagrams (Context ID 0), UDP relay, HTTP Basic authentication, plain HTTP/3 CONNECT, and graceful shutdown.

The current maintenance release is `v1.0.4`. See
[`docs/architecture.md`](docs/architecture.md) for the canonical data paths,
ownership rules, limits, and frozen performance boundary; see
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for deployment validation and
[`docs/maintenance.md`](docs/maintenance.md) for release gates.

Build:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o dist/jiejie-masque-linux-amd64 ./cmd/jiejie-masque
```

Run or validate either independent mode:

```sh
jiejie-masque serve --config /etc/jiejie-masque/connect-ip.yaml
jiejie-masque check-config --config /etc/jiejie-masque/connect-ip.yaml
jiejie-masque serve --config /etc/jiejie-masque/connect-udp.yaml
jiejie-masque check-config --config /etc/jiejie-masque/connect-udp.yaml

# Prints a ready-to-paste modern Mihomo CONNECT-IP node. The private key is
# intentionally only emitted when supplied explicitly to this command.
jiejie-masque mihomo-config --config /etc/jiejie-masque/connect-ip.yaml --server vpn.example.com --port 443 --private-key BASE64_KEY
```

The modes use separate YAML files, listeners, reset-key paths and systemd services. CONNECT-IP requires `CAP_NET_ADMIN`, a TUN device, and network preparation. CONNECT-UDP requires none of those privileges and must not receive `CAP_NET_ADMIN`.

For a small provider, keep CONNECT-UDP authenticated and bounded: use `auth.users` with `password_env`, `max_active_flows: 256`, `max_active_flows_per_user: 64`, and `flow_idle_timeout: 1h`. Never enable unauthenticated mode on a publicly reachable proxy. CONNECT-IP shared-profile mode still permits concurrent sessions using the same Mihomo key and visible tunnel IP; its optional per-client session cap only limits runaway reconnects.

Privacy: runtime logs deliberately omit client identities, tunnel addresses, relay destinations, and resolved next-hop addresses. CONNECT-UDP responses similarly avoid exposing raw network errors or resolved destination IPs. Keep service configuration and environment files owner-readable only (for example, `chmod 600 /etc/jiejie-masque/*.yaml /etc/jiejie-masque/*.env`).

Formal releases are produced by the tag-triggered GitHub Actions workflow,
which validates the annotated tag, builds once, and uploads that exact
artifact. For local reproduction or audit only, check out an annotated tag
and run:

```sh
TAG="${TAG:?set a release tag such as v1.0.3}"
VERSION="${TAG#v}" \
COMMIT="$(git rev-list -n1 "$TAG")" \
scripts/build-release.sh
```

The wrapper requires explicit metadata and produces the stripped static Linux
amd64 binary, SHA256 metadata, and `dist/RELEASE.txt`. Ordinary development
builds may use `go build ./cmd/jiejie-masque`.

Loopback HTTP/3 integration tests cover both CONNECT-UDP datagram relay and plain CONNECT TCP relay. Production migration remains out of scope. Preserve the existing CONNECT-IP P-256 certificate/private key because clients pin its public key.

CONNECT-IP includes a DNS gateway by default. It listens only at the server tunnel address (for example `10.200.0.1:5353`) and relays UDP and TCP DNS to `127.0.0.1:53`; it never opens a public DNS listener or falls back to a public resolver. The generated Mihomo node enables `remote-dns-resolve` and uses `udp://10.200.0.1:5353`. Current Mihomo MASQUE documentation supports MIPS `bbr3` for the inner TCP stack and `bbr` with the `standard` profile for the outer client sender.
