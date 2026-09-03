# Third-party notices

See `go.mod` and `NOTICE` for dependency and license notices. Runtime dependencies use the MetaCubeX QUIC, HTTP, TLS, and CONNECT-IP modules.

CONNECT-UDP server-side relay behavior was adapted from the MIT-licensed `github.com/quic-go/masque-go` v0.4.0 reference implementation. The final binary does not depend on that module or on upstream quic-go; it uses the MetaCubeX forked QUIC/HTTP/3 substrate.
