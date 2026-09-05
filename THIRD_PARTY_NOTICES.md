# Third-party notices

See `go.mod` and `NOTICE` for dependency and license notices. Runtime dependencies use the MetaCubeX QUIC, HTTP, TLS, and CONNECT-IP modules.

## MetaCubeX quic-go and the CONNECT-IP CUBIC selector fork

The CONNECT-IP congestion-control selector uses the MIT-licensed
`github.com/Piggy-Cat-bit-shadow/quic-go` fork at commit
`a0f328dde1d9`, based on MIT-licensed
`github.com/metacubex/quic-go` commit `2548683b76f4`. The fork exposes only
the upstream native CUBIC selector, bounded DATAGRAM ownership and borrowed-
parser changes, and the explicit HTTP/3 DATAGRAM polling API used by this
project; it contains no BBR code. See
`docs/CONNECT_IP_QUIC_CONGESTION.md` for the upstream and license provenance.

CONNECT-UDP server-side relay behavior was adapted from the MIT-licensed `github.com/quic-go/masque-go` v0.4.0 reference implementation. The final binary does not depend on that module or on upstream quic-go; it uses the MetaCubeX forked QUIC/HTTP/3 substrate.

## quic-go/masque-go v0.4.0

Portions of CONNECT-UDP request parsing, capsule handling, HTTP Datagram relay, and server-side proxy lifecycle are adapted from `github.com/quic-go/masque-go` v0.4.0.

Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## WireGuard-go Linux TUN GSO splitter

The optional Linux CONNECT-IP `tun_offload` receive path and `tun_tx_gro` TCP
transmit path retain minimal adaptations of `tun/offload_linux.go` and the virtio-header parsing behavior
from [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go) commit
`ecfc5a8d54462e18e13c72173e2623d16d8e25a0`: only TCP GSO splitting, ordered
TCP GRO coalescing, checksum repair, and the `virtio_net_hdr` ABI handling are included. No
WireGuard protocol or device code is included. The source is MIT licensed:

Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
