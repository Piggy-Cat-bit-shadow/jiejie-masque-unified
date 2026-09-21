# Lean CONNECT-IP architecture

The service has one application protocol: CONNECT-IP. An authenticated HTTP/3
connection owns at most one CONNECT-IP session. TUN packets are read and
written directly through a bounded packet pool; packet ownership is transferred
to the maintained connect-ip-go connection on write and released by that API.

The QUIC fork supplies DATAGRAM backpressure, pacing, congestion control and
outer UDP GSO. TUN VNET_HDR/GSO/GRO experiments are intentionally absent from
the production path. The server performs host-network checks during startup
only, sends a single systemd READY notification, and shuts down with bounded
HTTP/3 cleanup.

Runtime diagnostics are aggregate and identity-free. They retain lifetime
counters and emit interval rates every 30 seconds; they never emit packet-level
logs, client keys, tunnel addresses, or target identities.
