package session

import (
	"context"
	"net/netip"
	"testing"
)

type managerTestConn struct {
	closed bool
}

func (c *managerTestConn) ReadPacket() ([]byte, error)        { return nil, context.Canceled }
func (c *managerTestConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (c *managerTestConn) Close() error                       { c.closed = true; return nil }

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
