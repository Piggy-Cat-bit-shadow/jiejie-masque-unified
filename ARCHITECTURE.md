# Architecture

One Go module and binary. CONNECT-IP remains an independent engine with TUN, session NAT, mTLS, a lightweight systemd runtime heartbeat, and an independent host-network deep probe. The heartbeat only demonstrates that the service runtime can schedule and notify systemd; it does not prove QUIC or packet datapath progress. CONNECT-UDP is a separate engine with its own configuration and service, signal-aware graceful shutdown, and the same systemd lifecycle contract.
