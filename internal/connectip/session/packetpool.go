package session

import "sync"

// PacketPool owns fixed-capacity TUN-to-session packet buffers. Packets larger
// than the configured TUN MTU are deliberately not pooled.
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
	p.pool.New = func() any { b := make([]byte, size+1); return &PacketBuffer{Buffer: b, Data: b[1:], pooled: true} }
	return p
}

func (p *PacketPool) Get(n int) *PacketBuffer {
	if n > p.size {
		b := make([]byte, n+1)
		return &PacketBuffer{Buffer: b, Data: b[1:]}
	}
	packet := p.pool.Get().(*PacketBuffer)
	packet.Data = packet.Buffer[1 : 1+n]
	return packet
}

func (p *PacketPool) Put(packet *PacketBuffer) {
	if packet != nil && packet.pooled && len(packet.Buffer) == p.size+1 {
		packet.Data = packet.Buffer[1:]
		p.pool.Put(packet)
	}
}
