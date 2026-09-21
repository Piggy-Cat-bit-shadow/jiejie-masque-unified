package session

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/quic-go"
)

type managerTestConn struct {
	mu     sync.Mutex
	stats  quic.RuntimeStats
	closed bool
}

func (c *managerTestConn) ReadPacket([]byte) (int, error)     { return 0, context.Canceled }
func (c *managerTestConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (c *managerTestConn) RuntimeStats() quic.RuntimeStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}
func (c *managerTestConn) Close() error                 { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *managerTestConn) setStats(s quic.RuntimeStats) { c.mu.Lock(); c.stats = s; c.mu.Unlock() }

func TestManagerDualStackTakeoverAndIdentityExclusion(t *testing.T) {
	m := NewManager(2)
	v4 := netip.MustParseAddr("10.20.0.2")
	v6 := netip.MustParseAddr("2001:db8:1::2")
	old := NewWithAddresses(context.Background(), []netip.Addr{v4, v6}, "client-a", &managerTestConn{}, nil)
	if got, err := m.Replace(old); err != nil || len(got) != 0 {
		t.Fatalf("first register: old=%v err=%v", got, err)
	}
	if m.Lookup(v4) != old || m.Lookup(v6) != old || m.Len() != 1 {
		t.Fatal("dual-stack addresses did not map atomically")
	}
	next := NewWithAddresses(context.Background(), []netip.Addr{v4, v6}, "client-a", &managerTestConn{}, nil)
	previous, err := m.Replace(next)
	if err != nil || len(previous) != 1 || m.Lookup(v4) != next || m.Lookup(v6) != next {
		t.Fatalf("takeover failed: %v %v", previous, err)
	}
	if !old.Conn.(*managerTestConn).closed {
		t.Fatal("replaced connection was not closed")
	}
	conflict := New(v4, "client-b", &managerTestConn{}, nil)
	if _, err = m.Replace(conflict); err == nil {
		t.Fatal("different identity took an owned address")
	}
	if m.Lookup(v4) != next {
		t.Fatal("rejected registration changed current owner")
	}
}

func TestManagerSessionLimit(t *testing.T) {
	m := NewManager(1)
	a := New(netip.MustParseAddr("10.0.0.2"), "a", &managerTestConn{}, nil)
	if _, err := m.Replace(a); err != nil {
		t.Fatal(err)
	}
	b := New(netip.MustParseAddr("10.0.0.3"), "b", &managerTestConn{}, nil)
	if _, err := m.Replace(b); err == nil {
		t.Fatal("session limit was not enforced")
	}
}

func TestAggregateRuntimeCountersMonotonicAcrossGenerationChurn(t *testing.T) {
	m := NewManager()
	c1 := &managerTestConn{}
	c1.setStats(quic.RuntimeStats{PacketsLost: 3, UDPWrites: 9, UDPWireBytes: 100, GSOMultiSegmentWrites: 2, GSOSegmentsTotal: 6})
	s1 := New(netip.MustParseAddr("10.0.0.2"), "a", c1, nil)
	if _, err := m.Replace(s1); err != nil {
		t.Fatal(err)
	}
	_ = m.AggregateRuntimeStats()
	s1.Close()
	c2 := &managerTestConn{}
	c2.setStats(quic.RuntimeStats{PacketsLost: 1, UDPWrites: 2, UDPWireBytes: 40, GSOMultiSegmentWrites: 1, GSOSegmentsTotal: 3})
	s2 := New(netip.MustParseAddr("10.0.0.3"), "b", c2, nil)
	if _, err := m.Replace(s2); err != nil {
		t.Fatal(err)
	}
	got := m.AggregateRuntimeStats()
	if got.PacketsLost != 4 || got.UDPWrites != 11 || got.UDPWireBytes != 140 || got.GSOMultiSegmentWrites != 3 || got.GSOSegmentsTotal != 9 {
		t.Fatalf("aggregate counters = %+v", got)
	}
	s2.Close()
	if m.Len() != 0 {
		t.Fatal("closed session remains registered")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	c := &managerTestConn{}
	s := New(netip.MustParseAddr("10.0.0.2"), "a", c, nil)
	s.Close()
	s.Close()
	if !c.closed {
		t.Fatal("connection was not closed")
	}
	if s.Ctx.Err() != context.Canceled {
		t.Fatalf("context err = %v", s.Ctx.Err())
	}
}
