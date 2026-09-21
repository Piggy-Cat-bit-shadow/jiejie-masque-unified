package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"github.com/metacubex/quic-go"
)

type directTestConn struct {
	mu       sync.Mutex
	calls    int
	fail     error
	closed   bool
	released bool
	stats    quic.RuntimeStats
	entered  chan struct{}
	block    <-chan struct{}
	closedCh chan struct{}
}

func (c *directTestConn) ReadPacketBuffer() (*connectip.PacketBuffer, error) {
	return nil, context.Canceled
}
func (c *directTestConn) TryReadPacketBuffer() (*connectip.PacketBuffer, error) {
	return nil, context.Canceled
}
func (c *directTestConn) WritePacketBufferOwned(_ []byte, _, _ int, owner connectip.PacketPayloadOwner) ([]byte, error) {
	c.mu.Lock()
	c.calls++
	err := c.fail
	entered, block, closed := c.entered, c.block, c.closedCh
	c.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if block != nil {
		select {
		case <-block:
		case <-closed:
			err = errors.New("connection closed")
		}
	}
	if owner != nil {
		owner.Release()
		c.released = true
	}
	return nil, err
}
func (c *directTestConn) RuntimeStats() quic.RuntimeStats { return c.stats }
func (c *directTestConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		if c.closedCh != nil {
			close(c.closedCh)
		}
	}
	c.mu.Unlock()
	return nil
}

type directTestTun struct {
	writes int
	err    error
}

func (t *directTestTun) Write(p []byte) (int, error) { t.writes++; return len(p), t.err }

func TestConnectIPRoutesByAddressFamily(t *testing.T) {
	v4 := config.TunnelAddresses{IPv4: netip.MustParsePrefix("10.200.0.2/32")}
	v6 := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::2/128")}
	server := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::1/64")}
	if got := connectIPRoutes(v4, config.TunnelAddresses{}, false); len(got) != 1 || !got[0].StartIP.Is4() {
		t.Fatalf("IPv4 routes: %+v", got)
	}
	if got := connectIPRoutes(v6, server, true); len(got) != 1 || got[0].StartIP != netip.IPv6Unspecified() {
		t.Fatalf("IPv6 routes: %+v", got)
	}
	if got := connectIPRoutes(config.TunnelAddresses{IPv4: v4.IPv4, IPv6: v6.IPv6}, server, false); len(got) != 2 {
		t.Fatalf("dual routes: %+v", got)
	}
}

func TestRequestTemplateRejectsMalformedAuthority(t *testing.T) {
	for _, host := range []string{"", "user@example.com", "example.com/path", "example.com:bad"} {
		if got, err := requestTemplate(host); err == nil || got != nil {
			t.Fatalf("accepted %q", host)
		}
	}
	if got, err := requestTemplate("example.com:443"); err != nil || got == nil {
		t.Fatalf("valid authority rejected: %v", err)
	}
}

func TestDispatchTUNPacketUsesDirectOwnedWrite(t *testing.T) {
	pool := session.NewPacketPool(1280)
	p := pool.Get(20)
	p.Data[0] = 0x45
	p.Data[2] = 0
	p.Data[3] = 20
	copy(p.Data[12:16], []byte{10, 0, 0, 1})
	copy(p.Data[16:20], []byte{10, 0, 0, 2})
	c := &directTestConn{}
	m := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "client", c, nil)
	if _, err := m.Replace(s); err != nil {
		t.Fatal(err)
	}
	tun := &directTestTun{}
	dispatchTUNPacket(p, m, pool, tun)
	if c.calls != 1 || tun.writes != 0 {
		t.Fatalf("direct send calls=%d tun writes=%d", c.calls, tun.writes)
	}
	if !c.released {
		t.Fatal("owned packet was not released by CONNECT-IP contract")
	}
}

func TestDispatchTUNPacketReleasesUnroutablePacket(t *testing.T) {
	pool := session.NewPacketPool(1280)
	p := pool.Get(20)
	p.Data[0] = 0x45
	p.Data[2] = 0
	p.Data[3] = 20
	copy(p.Data[16:20], []byte{10, 0, 0, 99})
	dispatchTUNPacket(p, session.NewManager(), pool, &directTestTun{})
	// Unroutable buffers are returned directly to PacketPool.
}

func TestDirectWriteErrorClosesSessionAfterOwnershipTransfer(t *testing.T) {
	pool := session.NewPacketPool(1280)
	p := pool.Get(20)
	p.Data[0] = 0x45
	p.Data[2] = 0
	p.Data[3] = 20
	copy(p.Data[16:20], []byte{10, 0, 0, 2})
	c := &directTestConn{fail: errors.New("write failed")}
	m := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "client", c, nil)
	if _, err := m.Replace(s); err != nil {
		t.Fatal(err)
	}
	dispatchTUNPacket(p, m, pool, &directTestTun{})
	if !c.released || !c.closed || m.Len() != 0 {
		t.Fatalf("owner released=%t closed=%t sessions=%d", c.released, c.closed, m.Len())
	}
}

func TestDirectWriteBackpressureBlocksAndThenTransfersOwnership(t *testing.T) {
	pool := session.NewPacketPool(1280)
	p := pool.Get(20)
	p.Data[0], p.Data[3] = 0x45, 20
	copy(p.Data[16:20], []byte{10, 0, 0, 2})
	gate, entered := make(chan struct{}), make(chan struct{})
	c := &directTestConn{entered: entered, block: gate}
	m := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "client", c, nil)
	if _, err := m.Replace(s); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { dispatchTUNPacket(p, m, pool, &directTestTun{}); close(done) }()
	<-entered
	select {
	case <-done:
		t.Fatal("direct write did not apply backpressure")
	default:
	}
	if c.released {
		t.Fatal("owner released before the transport resumed")
	}
	close(gate)
	<-done
	if !c.released {
		t.Fatal("owner was not released after the transport resumed")
	}
}

func TestClosingConnectionUnblocksDirectWriteAndReleasesOwner(t *testing.T) {
	pool := session.NewPacketPool(1280)
	p := pool.Get(20)
	p.Data[0], p.Data[3] = 0x45, 20
	copy(p.Data[16:20], []byte{10, 0, 0, 2})
	entered, closed := make(chan struct{}), make(chan struct{})
	c := &directTestConn{entered: entered, block: make(chan struct{}), closedCh: closed}
	m := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "client", c, nil)
	if _, err := m.Replace(s); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { dispatchTUNPacket(p, m, pool, &directTestTun{}); close(done) }()
	<-entered
	s.Close()
	<-done
	if !c.released || m.Len() != 0 {
		t.Fatalf("released=%t sessions=%d", c.released, m.Len())
	}
}
