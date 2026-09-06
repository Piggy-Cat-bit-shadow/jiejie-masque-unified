//go:build linux

package connectudp

import (
	"io"
	"net"

	"golang.org/x/net/ipv4"
)

type udpWriteBatch struct {
	conn          *net.UDPConn
	packet        *ipv4.PacketConn
	messages      [udpReadBatchSize]ipv4.Message
	messageBuffer [udpReadBatchSize][1][]byte
}

func newUDPWriteBatch(conn *net.UDPConn) *udpWriteBatch {
	return &udpWriteBatch{conn: conn, packet: ipv4.NewPacketConn(conn)}
}

func (b *udpWriteBatch) Write(payloads [][]byte) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	// x/net's vectored message contract requires a non-empty buffer. Preserve
	// legal zero-length UDP datagrams through the portable one-write path.
	for _, payload := range payloads {
		if len(payload) == 0 {
			written := 0
			for _, p := range payloads {
				if _, err := b.conn.Write(p); err != nil {
					return written, err
				}
				written++
			}
			return written, nil
		}
	}
	for i, payload := range payloads {
		b.messageBuffer[i][0] = payload
		b.messages[i].Buffers = b.messageBuffer[i][:]
	}
	n, err := b.packet.WriteBatch(b.messages[:len(payloads)], 0)
	if err == nil && n != len(payloads) {
		err = io.ErrShortWrite
	}
	return n, err
}
