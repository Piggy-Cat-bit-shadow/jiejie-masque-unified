package session

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
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
		s.Outbound <- &PacketBuffer{Data: []byte{1}}
	}
	select {
	case s.Outbound <- &PacketBuffer{Data: []byte{2}}:
		t.Fatal("queue accepted packet beyond capacity")
	default:
	}
	s.Close()
}

func TestCloseDrainsOutboundAndRejectsNewPackets(t *testing.T) {
	pool := NewPacketPool(1280)
	s := NewWithContextAndPacketPool(context.Background(), netip.MustParseAddr("10.200.0.2"), "client", &fakeConn{}, pool, nil)
	if !s.TryEnqueue(pool.Get(1280)) {
		t.Fatal("enqueue failed")
	}
	s.Close()
	if len(s.Outbound) != 0 {
		t.Fatalf("queued packets after close = %d", len(s.Outbound))
	}
	if s.TryEnqueue(pool.Get(1280)) {
		t.Fatal("closed session accepted packet")
	}
}

func TestQueueTracksHighWaterAndBoundedOverflow(t *testing.T) {
	pool := NewPacketPool(1280)
	s := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.200.0.2"), "client", &fakeConn{}, pool, 2, nil)
	defer s.Close()
	if !s.TryEnqueue(pool.Get(10)) || !s.TryEnqueue(pool.Get(10)) {
		t.Fatal("queue did not accept its bounded burst")
	}
	if s.QueueHighWater() != 2 {
		t.Fatalf("high water = %d, want 2", s.QueueHighWater())
	}
	if s.TryEnqueue(pool.Get(10)) {
		t.Fatal("queue accepted packet beyond capacity")
	}
	if s.QueueDropped() != 1 {
		t.Fatalf("dropped = %d, want 1", s.QueueDropped())
	}
	stats := s.QueueStats()
	if stats.Capacity != 2 || stats.Depth != 2 || stats.HighWater != 2 || stats.Enqueued != 2 || stats.Dequeued != 0 || stats.Dropped != 1 {
		t.Fatalf("queue stats = %+v", stats)
	}
}

func TestSlowSessionQueueDoesNotBlockFastSession(t *testing.T) {
	pool := NewPacketPool(1280)
	slow := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.200.0.2"), "slow", &fakeConn{}, pool, 2, nil)
	fast := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.200.0.3"), "fast", &fakeConn{}, pool, 2, nil)
	defer slow.Close()
	defer fast.Close()

	// Deliberately leave slow's writer stalled and fill its small bounded queue.
	if !slow.TryEnqueue(pool.Get(10)) || !slow.TryEnqueue(pool.Get(10)) || slow.TryEnqueue(pool.Get(10)) {
		t.Fatal("slow queue did not apply bounded backpressure")
	}
	for i := 0; i < 128; i++ {
		if !fast.TryEnqueue(pool.Get(10)) {
			t.Fatalf("fast session dropped packet %d while another session was stalled", i)
		}
		packet := <-fast.Outbound
		fast.RecordDequeued()
		fast.ReleasePacket(packet)
	}
	if got := slow.QueueStats(); got.Dropped != 1 || got.Depth != 2 {
		t.Fatalf("slow queue stats = %+v", got)
	}
	if got := fast.QueueStats(); got.Dropped != 0 || got.Enqueued != 128 || got.Dequeued != 128 || got.Depth != 0 {
		t.Fatalf("fast queue stats = %+v", got)
	}
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

// Pending cleanup must reserve the shadow address even when reuse_delay is
// zero and after a positive delay would otherwise have expired.
func TestShadowCleanupPendingAddressUnavailable(t *testing.T) {
	for _, delay := range []time.Duration{0, 10 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			var now = time.Unix(100, 0)
			release := make(chan struct{})
			started := make(chan netip.Addr, 1)
			m := NewShadowManagerWithClock(netip.MustParsePrefix("10.200.0.128/30"), 2, nil, delay, func() time.Time { return now }, func(uint32) uint32 { return 0 })
			defer m.CloseCleanup()
			m.SetShadowCleanup(func(ip netip.Addr) error {
				started <- ip
				<-release
				return nil
			})
			defer close(release)
			newSession := func(identity string) *Session {
				return New(netip.MustParseAddr("10.200.0.2"), identity, &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
			}
			a, b := newSession("a"), newSession("b")
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			if err := m.Register(b); err != nil {
				t.Fatal(err)
			}
			a.Close()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("cleanup did not start")
			}
			now = now.Add(time.Second)
			c := newSession("c")
			if err := m.Register(c); err == nil {
				t.Fatal("pending cleanup address was reused before cleanup completed")
			}
			b.Close()
		})
	}
}

func TestShadowCleanupConcurrencyBounded(t *testing.T) {
	const n = 128
	var active, maxActive atomic.Int32
	started := make(chan struct{}, n)
	release := make(chan struct{})
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.200.0.0/24"), n, nil, 0, time.Now, func(uint32) uint32 { return 0 })
	defer m.CloseCleanup()
	m.SetShadowCleanup(func(netip.Addr) error {
		current := active.Add(1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return nil
	})
	sessions := make([]*Session, 0, n)
	for i := 0; i < n; i++ {
		s := New(netip.MustParseAddr("10.200.0.2"), "shared", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
		if err := m.Register(s); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		s.Close()
	}
	deadline := time.After(time.Second)
	for len(started) == 0 {
		select {
		case <-deadline:
			t.Fatal("cleanup did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if maxActive.Load() > 2 {
		t.Fatalf("cleanup concurrency exceeded fixed worker bound: max=%d", maxActive.Load())
	}
	close(release)
	deadline = time.After(time.Second)
	for m.CleanupStats().Completed < n {
		select {
		case <-deadline:
			t.Fatalf("only %d/%d cleanup callbacks completed", m.CleanupStats().Completed, n)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestShadowCleanupExecutorBackpressureAndWorkerSurvival(t *testing.T) {
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.200.0.0/29"), 1, nil, 0, time.Now, func(uint32) uint32 { return 0 })
	defer m.CloseCleanup()
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	m.SetShadowCleanup(func(ip netip.Addr) error {
		started <- struct{}{}
		<-release
		if ip == netip.MustParseAddr("10.200.0.1") {
			return errors.New("expected cleanup error")
		}
		return nil
	})
	e := m.cleanupExecutor
	jobs := []cleanupJob{
		{manager: m, ip: netip.MustParseAddr("10.200.0.1"), cleanup: m.cleanup},
		{manager: m, ip: netip.MustParseAddr("10.200.0.2"), cleanup: m.cleanup},
		{manager: m, ip: netip.MustParseAddr("10.200.0.3"), cleanup: m.cleanup},
		{manager: m, ip: netip.MustParseAddr("10.200.0.4"), cleanup: m.cleanup},
	}
	for _, job := range jobs {
		m.cleanupPending[job.ip] = struct{}{}
	}
	if !e.enqueue(jobs[0]) || !e.enqueue(jobs[1]) {
		t.Fatal("initial cleanup jobs were not accepted")
	}
	thirdDone := make(chan bool, 1)
	go func() {
		if !e.enqueue(jobs[2]) {
			thirdDone <- false
			return
		}
		thirdDone <- e.enqueue(jobs[3])
	}()
	select {
	case <-thirdDone:
		t.Fatal("queue-full enqueue did not apply backpressure")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case accepted := <-thirdDone:
		if !accepted {
			t.Fatal("backpressured cleanup job was dropped during normal operation")
		}
	case <-time.After(time.Second):
		t.Fatal("backpressured cleanup job was not accepted")
	}
	deadline := time.After(time.Second)
	for stats := m.CleanupStats(); stats.Completed+stats.Failed < 4; stats = m.CleanupStats() {
		select {
		case <-deadline:
			t.Fatalf("cleanup workers did not survive error: %+v", m.CleanupStats())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	stats := m.CleanupStats()
	if stats.Failed != 1 || stats.Completed != 3 || stats.MaxActive > shadowCleanupWorkers {
		t.Fatalf("unexpected cleanup stats: %+v", stats)
	}
}

func TestShadowCleanupShutdownDropsQueuedWork(t *testing.T) {
	const n = 4
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.203.0.0/24"), n, nil, 0, time.Now, func(uint32) uint32 { return 0 })
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	started := make(chan struct{}, n)
	defer m.CloseCleanup()
	m.SetShadowCleanup(func(netip.Addr) error {
		started <- struct{}{}
		<-release
		return nil
	})
	defer releaseAll()
	sessions := make([]*Session, 0, n)
	for i := 0; i < n; i++ {
		s := New(netip.MustParseAddr("10.200.0.2"), "shutdown", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
		if err := m.Register(s); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		s.Close()
	}
	deadline := time.After(time.Second)
	for len(started) < shadowCleanupWorkers {
		select {
		case <-deadline:
			t.Fatalf("only %d cleanup workers started", len(started))
		default:
			time.Sleep(time.Millisecond)
		}
	}
	closed := make(chan struct{})
	go func() {
		m.CloseCleanup()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("shutdown returned while cleanup callbacks were still running")
	case <-time.After(20 * time.Millisecond):
	}
	releaseAll()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not wait for running cleanup callbacks")
	}
	stats := m.CleanupStats()
	if stats.Started != shadowCleanupWorkers || stats.Completed != shadowCleanupWorkers || stats.Dropped != n-shadowCleanupWorkers {
		t.Fatalf("shutdown drained queued cleanup unexpectedly: %+v", stats)
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
	defer m.CloseCleanup()
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
	deadline := time.After(time.Second)
	for stats := m.CleanupStats(); stats.Completed+stats.Failed < 1; stats = m.CleanupStats() {
		select {
		case <-deadline:
			t.Fatal("cleanup did not complete")
		default:
			time.Sleep(time.Millisecond)
		}
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
