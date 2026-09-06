//go:build linux

package connectudp

import (
	"net"

	"golang.org/x/net/ipv4"
)

// udpReadBatchSize bounds one target socket readiness round. ipv4.PacketConn
// uses recvmmsg on Linux and falls back to the runtime's normal readiness
// handling when the socket has no immediately available datagrams.
const udpReadBatchSize = 16

type udpReadBatch struct {
	conn     *ipv4.PacketConn
	buffers  [udpReadBatchSize]*udpOwnedDatagram
	messages [udpReadBatchSize]ipv4.Message
}

func newUDPReadBatch(conn *net.UDPConn) *udpReadBatch {
	return &udpReadBatch{conn: ipv4.NewPacketConn(conn)}
}

// Read acquires the complete bounded batch before entering recvmmsg. The
// caller owns every acquired entry and must release entries at and beyond n,
// as well as entries it does not hand to QUIC.
func (b *udpReadBatch) Read(pool *udpOwnedDatagramPool) (int, error) {
	for i := range b.buffers {
		buffer := pool.Acquire()
		b.buffers[i] = buffer
		b.messages[i].Buffers = [][]byte{buffer.data[udpPayloadOffset : udpPayloadOffset+maxUDPPayloadSize+1]}
		b.messages[i].N = 0
	}
	return b.conn.ReadBatch(b.messages[:], 0)
}

func (b *udpReadBatch) packetLen(i int) int { return b.messages[i].N }

func (b *udpReadBatch) releaseFrom(n int) {
	if n < 0 {
		n = 0
	}
	for i := n; i < len(b.buffers); i++ {
		if b.buffers[i] != nil {
			b.buffers[i].Release()
			b.buffers[i] = nil
		}
	}
}
