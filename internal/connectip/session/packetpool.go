package session

import (
	"sync"
	"sync/atomic"
)

const (
	// PacketPoolHeadroom reserves the maximum HTTP/3 quarter-stream-ID prefix
	// plus the one-byte CONNECT-IP Context ID prefix.
	PacketPoolHeadroom = 9
	packetReadSentinel = 1
)

// PacketPool owns fixed-capacity TUN-to-session packet buffers. Each backing
// allocation reserves HTTP/3 and CONNECT-IP headroom plus one read sentinel byte:
// the latter lets the dispatcher reject an oversized TUN read without silently
// accepting a truncated packet. Queued packet payloads remain MTU-sized.
type PacketPool struct {
	size int
	pool sync.Pool
}

type PacketBuffer struct {
	Buffer   []byte
	Data     []byte
	pooled   bool
	pool     *PacketPool
	released atomic.Bool
}

func NewPacketPool(size int) *PacketPool {
	p := &PacketPool{size: size}
	p.pool.New = func() any {
		b := make([]byte, size+PacketPoolHeadroom+packetReadSentinel)
		return &PacketBuffer{Buffer: b, Data: b[PacketPoolHeadroom : PacketPoolHeadroom+size], pooled: true, pool: p}
	}
	return p
}

func (p *PacketPool) PayloadSize() int { return p.size }

func (p *PacketPool) Get(n int) *PacketBuffer {
	if n > p.size {
		b := make([]byte, n+PacketPoolHeadroom)
		return &PacketBuffer{Buffer: b, Data: b[PacketPoolHeadroom:]}
	}
	packet := p.pool.Get().(*PacketBuffer)
	packet.released.Store(false)
	packet.Data = packet.Buffer[PacketPoolHeadroom : PacketPoolHeadroom+n]
	return packet
}

// AcquireForRead returns a pooled buffer whose Data slice has one byte more
// than the configured payload MTU. Call CommitRead with the read length before
// routing or enqueueing it; a false result means the TUN packet exceeded MTU.
func (p *PacketPool) AcquireForRead() *PacketBuffer {
	packet := p.pool.Get().(*PacketBuffer)
	packet.released.Store(false)
	packet.Data = packet.Buffer[PacketPoolHeadroom:]
	return packet
}

// CommitRead narrows a direct TUN read to its payload length. It rejects the
// sentinel byte and larger values, so callers never enqueue truncated packets.
func (p *PacketPool) CommitRead(packet *PacketBuffer, n int) bool {
	if packet == nil || !packet.pooled || n < 0 || n > p.size {
		return false
	}
	packet.Data = packet.Buffer[PacketPoolHeadroom : PacketPoolHeadroom+n]
	return true
}

func (p *PacketPool) Put(packet *PacketBuffer) {
	if packet != nil && packet.pooled && packet.pool == p && len(packet.Buffer) == p.size+PacketPoolHeadroom+packetReadSentinel && packet.released.CompareAndSwap(false, true) {
		packet.Data = packet.Buffer[PacketPoolHeadroom : PacketPoolHeadroom+p.size]
		p.pool.Put(packet)
	}
}

// Release returns a pooled packet exactly once. It is intentionally a method
// on the buffer so asynchronous QUIC ownership needs no closure allocation.
func (p *PacketBuffer) Release() {
	if p != nil && p.pool != nil {
		p.pool.Put(p)
	}
}
