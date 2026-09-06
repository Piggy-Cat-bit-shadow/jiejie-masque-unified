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
	conn          *ipv4.PacketConn
	buffers       [udpReadBatchSize]*udpOwnedDatagram
	messages      [udpReadBatchSize]ipv4.Message
	messageBuffer [udpReadBatchSize][1][]byte
}

func newUDPReadBatch(conn *net.UDPConn) *udpReadBatch {
	return &udpReadBatch{conn: ipv4.NewPacketConn(conn)}
}

// Read retains unused slots between readiness rounds. A slot handed to QUIC is
// set to nil by the caller and receives a fresh ownership generation next
// round; retained slots are never released while the socket remains active.
func (b *udpReadBatch) Read(pool *udpOwnedDatagramPool) (int, error) {
	for i := range b.buffers {
		if b.buffers[i] == nil {
			b.buffers[i] = pool.Acquire()
		}
		buffer := b.buffers[i]
		b.messageBuffer[i][0] = buffer.data[udpPayloadOffset : udpPayloadOffset+maxUDPPayloadSize+1]
		b.messages[i].Buffers = b.messageBuffer[i][:]
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

func (b *udpReadBatch) releaseAll() { b.releaseFrom(0) }
