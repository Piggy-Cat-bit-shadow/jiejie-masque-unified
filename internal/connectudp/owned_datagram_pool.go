package connectudp

import (
	"sync"
	"sync/atomic"

	"github.com/metacubex/quic-go"
)

const (
	maxHTTPDatagramPrefixLen = 8
	udpContextIDOffset       = maxHTTPDatagramPrefixLen
	udpPayloadOffset         = udpContextIDOffset + 1
	udpOwnedBufferLen        = udpPayloadOffset + maxUDPPayloadSize + 1
)

// udpOwnedDatagramPool owns buffers used until quic-go has either queued or
// rejected a datagram. Acquire starts a new ownership generation; Release is
// idempotent within that generation and returns the buffer to the pool.
type udpOwnedDatagramPool struct {
	pool sync.Pool
}

type udpOwnedDatagram struct {
	data     []byte
	pool     *udpOwnedDatagramPool
	released atomic.Bool
}

func newUDPOwnedDatagramPool() *udpOwnedDatagramPool {
	p := &udpOwnedDatagramPool{}
	p.pool.New = func() any {
		return &udpOwnedDatagram{data: make([]byte, udpOwnedBufferLen), pool: p}
	}
	return p
}

func (p *udpOwnedDatagramPool) Acquire() *udpOwnedDatagram {
	b := p.pool.Get().(*udpOwnedDatagram)
	b.released.Store(false)
	return b
}

func (b *udpOwnedDatagram) Release() {
	if b.released.CompareAndSwap(false, true) {
		b.pool.pool.Put(b)
	}
}

var _ quic.DatagramPayloadOwner = (*udpOwnedDatagram)(nil)
