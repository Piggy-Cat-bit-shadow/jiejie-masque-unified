package session

import "sync"

// PacketPool owns fixed-capacity TUN-to-session packet buffers. Packets larger
// than the configured TUN MTU are deliberately not pooled.
type PacketPool struct {
	size int
	pool sync.Pool
}

type PacketBuffer struct {
	Data   []byte
	pooled bool
}

func NewPacketPool(size int) *PacketPool {
	p := &PacketPool{size: size}
	p.pool.New = func() any { return &PacketBuffer{Data: make([]byte, size), pooled: true} }
	return p
}

func (p *PacketPool) Get(n int) *PacketBuffer {
	if n > p.size {
		return &PacketBuffer{Data: make([]byte, n)}
	}
	packet := p.pool.Get().(*PacketBuffer)
	packet.Data = packet.Data[:n]
	return packet
}

func (p *PacketPool) Put(packet *PacketBuffer) {
	if packet != nil && packet.pooled && cap(packet.Data) == p.size {
		packet.Data = packet.Data[:p.size]
		p.pool.Put(packet)
	}
}
