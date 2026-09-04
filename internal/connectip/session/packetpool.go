package session

import "sync"

// PacketPool owns fixed-capacity TUN-to-session packet buffers. Each backing
// allocation reserves one CONNECT-IP headroom byte and one read sentinel byte:
// the latter lets the dispatcher reject an oversized TUN read without silently
// accepting a truncated packet. Queued packet payloads remain MTU-sized.
type PacketPool struct {
	size int
	pool sync.Pool
}

type PacketBuffer struct {
	Buffer []byte
	Data   []byte
	pooled bool
}

func NewPacketPool(size int) *PacketPool {
	p := &PacketPool{size: size}
	p.pool.New = func() any {
		b := make([]byte, size+2)
		return &PacketBuffer{Buffer: b, Data: b[1 : 1+size], pooled: true}
	}
	return p
}

func (p *PacketPool) PayloadSize() int { return p.size }

func (p *PacketPool) Get(n int) *PacketBuffer {
	if n > p.size {
		b := make([]byte, n+1)
		return &PacketBuffer{Buffer: b, Data: b[1:]}
	}
	packet := p.pool.Get().(*PacketBuffer)
	packet.Data = packet.Buffer[1 : 1+n]
	return packet
}

// AcquireForRead returns a pooled buffer whose Data slice has one byte more
// than the configured payload MTU. Call CommitRead with the read length before
// routing or enqueueing it; a false result means the TUN packet exceeded MTU.
func (p *PacketPool) AcquireForRead() *PacketBuffer {
	packet := p.pool.Get().(*PacketBuffer)
	packet.Data = packet.Buffer[1:]
	return packet
}

// CommitRead narrows a direct TUN read to its payload length. It rejects the
// sentinel byte and larger values, so callers never enqueue truncated packets.
func (p *PacketPool) CommitRead(packet *PacketBuffer, n int) bool {
	if packet == nil || !packet.pooled || n < 0 || n > p.size {
		return false
	}
	packet.Data = packet.Buffer[1 : 1+n]
	return true
}

func (p *PacketPool) Put(packet *PacketBuffer) {
	if packet != nil && packet.pooled && len(packet.Buffer) == p.size+2 {
		packet.Data = packet.Buffer[1 : 1+p.size]
		p.pool.Put(packet)
	}
}
