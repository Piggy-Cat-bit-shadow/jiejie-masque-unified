# Lean CONNECT-IP architecture

The service has one application protocol: CONNECT-IP. An authenticated HTTP/3
connection owns at most one CONNECT-IP session. TUN packets are read and
written directly through the maintained connect-ip-go connection.

The QUIC fork supplies DATAGRAM backpressure, pacing, congestion control and
outer UDP GSO. TUN VNET_HDR/GSO/GRO experiments are intentionally absent from
the production path. The server performs host-network checks during startup
only, sends a single systemd READY notification, and shuts down with bounded
HTTP/3 cleanup.

The application layer does not maintain a second runtime-statistics or pipeline
telemetry subsystem. QUIC owns transport-level state; the service exposes only
its normal version and dependency provenance information.
