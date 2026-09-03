package session

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeConn struct{ closed int }

func (f *fakeConn) ReadPacket() ([]byte, error)        { return nil, errors.New("closed") }
func (f *fakeConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (f *fakeConn) Close() error                       { f.closed++; return nil }
func TestManagerConcurrentIPsAndTakeover(t *testing.T) {
	m := NewManager()
	a := New(netip.MustParseAddr("10.200.0.2"), "a", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	b := New(netip.MustParseAddr("10.200.0.3"), "b", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	m.Replace(a)
	m.Replace(b)
	if m.Len() != 2 {
		t.Fatal(m.Len())
	}
	a2 := New(a.ClientIP, "a2", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	m.Replace(a2)
	if m.Lookup(a.ClientIP) != a2 || m.Lookup(b.ClientIP) != b {
		t.Fatal("replace damaged registry")
	}
	if m.RemoveIfCurrent(a) {
		t.Fatal("stale remove succeeded")
	}
	if m.Lookup(a.ClientIP) != a2 {
		t.Fatal("stale removal deleted new session")
	}
	a2.Close()
	b.Close()
}

func TestPerClientReservationCapAndRelease(t *testing.T) {
	m := NewShadowManager(netip.MustParsePrefix("10.200.0.128/29"), 4, nil)
	m.SetMaxSessionsPerClient(2)
	r1, err := m.TryReserveFor("a")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := m.TryReserveFor("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.TryReserveFor("a"); err == nil {
		t.Fatal("same identity bypassed cap")
	}
	other, err := m.TryReserveFor("b")
	if err != nil {
		t.Fatal("other identity blocked: " + err.Error())
	}
	r1()
	r1()
	if _, err := m.TryReserveFor("a"); err != nil {
		t.Fatal("capacity not restored")
	}
	r2()
	other()
}

func TestPerClientConcurrentReservations(t *testing.T) {
	m := NewShadowManager(netip.MustParsePrefix("10.200.0.128/29"), 16, nil)
	m.SetMaxSessionsPerClient(2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var accepted int
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if release, err := m.TryReserveFor("shared"); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
				release()
			}
		}()
	}
	close(start)
	wg.Wait()
	if accepted == 0 {
		t.Fatal("no concurrent reservation succeeded")
	}
	if m.reserved != 0 || len(m.reservedByIdentity) != 0 {
		t.Fatalf("reservation leak: %d %v", m.reserved, m.reservedByIdentity)
	}
}

func TestManagerQueueIsBounded(t *testing.T) {
	m := NewManager()
	s := New(netip.MustParseAddr("10.200.0.2"), "a", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	m.Replace(s)
	if cap(s.Outbound) != DefaultOutboundQueueSize {
		t.Fatalf("queue capacity = %d, want %d", cap(s.Outbound), DefaultOutboundQueueSize)
	}
	for i := 0; i < cap(s.Outbound); i++ {
		s.Outbound <- []byte{1}
	}
	select {
	case s.Outbound <- []byte{2}:
		t.Fatal("queue accepted packet beyond capacity")
	default:
	}
	s.Close()
}

func TestShadowManagerAllowsSameVisibleIP(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.128/30")
	m := NewShadowManager(pool, 2, nil)
	a := New(netip.MustParseAddr("10.200.0.2"), "a", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	b := New(netip.MustParseAddr("10.200.0.2"), "b", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(b); err != nil {
		t.Fatal(err)
	}
	if a.ShadowIP == b.ShadowIP || m.Len() != 2 {
		t.Fatalf("shadow sessions = %s, %s; len=%d", a.ShadowIP, b.ShadowIP, m.Len())
	}
	if m.Lookup(a.ShadowIP) != a || m.Lookup(b.ShadowIP) != b {
		t.Fatal("shadow lookup mismatch")
	}
	a.Close()
	if m.Lookup(a.ShadowIP) != nil || m.Lookup(b.ShadowIP) != b {
		t.Fatal("closing A affected B")
	}
	c := New(netip.MustParseAddr("10.200.0.2"), "c", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	b.Close()
}

func TestShadowManagerReuseCooldown(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.200.0.128/30"), 2, nil, time.Minute, func() time.Time { return now }, func(uint32) uint32 { return 0 })
	a := New(netip.MustParseAddr("10.200.0.2"), "a", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	b := New(netip.MustParseAddr("10.200.0.2"), "b", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(b); err != nil {
		t.Fatal(err)
	}
	shadow := a.ShadowIP
	a.Close()
	c := New(netip.MustParseAddr("10.200.0.2"), "c", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(c); err == nil {
		t.Fatal("expected cooling address to be unavailable")
	}
	now = now.Add(time.Minute)
	if err := m.Register(c); err != nil {
		t.Fatal(err)
	}
	if c.ShadowIP != shadow {
		t.Fatalf("shadow = %s, want %s", c.ShadowIP, shadow)
	}
	b.Close()
	c.Close()
}

func TestShadowManagerAdmission(t *testing.T) {
	m := NewShadowManager(netip.MustParsePrefix("10.200.0.128/30"), 1, nil)
	release, err := m.TryReserve()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.TryReserve(); err == nil {
		t.Fatal("expected reserved capacity to reject a second session")
	}
	release()
}

func TestShadowManagerAllocatesManySameVisibleSessions(t *testing.T) {
	m := NewShadowManager(netip.MustParsePrefix("10.200.0.0/24"), 100, nil)
	sessions := make([]*Session, 0, 100)
	seen := map[netip.Addr]bool{}
	for i := 0; i < 100; i++ {
		s := New(netip.MustParseAddr("10.200.0.2"), "shared", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
		if err := m.Register(s); err != nil {
			t.Fatal(err)
		}
		if seen[s.ShadowIP] {
			t.Fatalf("duplicate shadow address %s", s.ShadowIP)
		}
		seen[s.ShadowIP] = true
		sessions = append(sessions, s)
	}
	if m.Len() != 100 {
		t.Fatalf("sessions = %d", m.Len())
	}
	for _, s := range sessions {
		s.Close()
	}
	if m.Len() != 0 {
		t.Fatalf("sessions after close = %d", m.Len())
	}
}

func TestSessionActivity(t *testing.T) {
	s := New(netip.MustParseAddr("10.200.0.2"), "test", &fakeConn{}, nil)
	when := time.Unix(123, 456)
	s.Touch(when)
	if got := s.LastActivity(); !got.Equal(when) {
		t.Fatalf("activity = %v", got)
	}
}

func TestShadowCleanupFailureStillCoolsAddress(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.200.0.128/30"), 1, nil, time.Hour, func() time.Time { return now }, func(uint32) uint32 { return 0 })
	called := make(chan netip.Addr, 1)
	m.SetShadowCleanup(func(ip netip.Addr) error { called <- ip; return errors.New("cleanup failed") })
	s := New(netip.MustParseAddr("10.200.0.2"), "test", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(s); err != nil {
		t.Fatal(err)
	}
	shadow := s.ShadowIP
	s.Close()
	select {
	case got := <-called:
		if got != shadow {
			t.Fatalf("cleanup address = %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup was not scheduled")
	}
	next := New(netip.MustParseAddr("10.200.0.2"), "next", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(next); err != nil {
		t.Fatal(err)
	}
	if next.ShadowIP == shadow {
		t.Fatal("cooling address was reused after cleanup failure")
	}
	next.Close()
}
