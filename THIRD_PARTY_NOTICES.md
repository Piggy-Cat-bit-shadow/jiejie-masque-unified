# Third-party notices

See `go.mod` and `NOTICE` for dependency and license notices. Runtime dependencies use the MetaCubeX QUIC, HTTP, TLS, and CONNECT-IP modules.

CONNECT-UDP server-side relay behavior was adapted from the MIT-licensed `github.com/quic-go/masque-go` v0.4.0 reference implementation. The final binary does not depend on that module or on upstream quic-go; it uses the MetaCubeX forked QUIC/HTTP/3 substrate.

## quic-go/masque-go v0.4.0

Portions of CONNECT-UDP request parsing, capsule handling, HTTP Datagram relay, and server-side proxy lifecycle are adapted from `github.com/quic-go/masque-go` v0.4.0.

Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
