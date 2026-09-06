//go:build !linux

package connectudp

import "net"

// Keep the same bounded ownership contract on platforms where x/net cannot
// issue recvmmsg. The portable path intentionally reads one datagram.
const udpReadBatchSize = 1

type udpReadBatch struct {
	conn    *net.UDPConn
	buffers [udpReadBatchSize]*udpOwnedDatagram
	sizes   [udpReadBatchSize]int
}

func newUDPReadBatch(conn *net.UDPConn) *udpReadBatch { return &udpReadBatch{conn: conn} }

func (b *udpReadBatch) Read(pool *udpOwnedDatagramPool) (int, error) {
	buffer := pool.Acquire()
	b.buffers[0] = buffer
	n, err := b.conn.Read(buffer.data[udpPayloadOffset : udpPayloadOffset+maxUDPPayloadSize+1])
	b.sizes[0] = n
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (b *udpReadBatch) packetLen(i int) int { return b.sizes[i] }

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
