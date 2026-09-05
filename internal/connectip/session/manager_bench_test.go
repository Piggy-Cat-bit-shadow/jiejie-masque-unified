package session

import (
	"net/netip"
	"testing"
	"time"
)

func benchmarkShadowManager(b *testing.B, pool string, max, initial int, reuseDelay time.Duration) (*Manager, []*Session) {
	b.Helper()
	m := NewShadowManagerWithClock(netip.MustParsePrefix(pool), max, nil, reuseDelay, time.Now, func(uint32) uint32 { return 0 })
	sessions := make([]*Session, 0, initial)
	for i := 0; i < initial; i++ {
		s := New(netip.MustParseAddr("10.200.0.2"), "bench", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
		if err := m.Register(s); err != nil {
			b.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	return m, sessions
}

func BenchmarkManagerLookup(b *testing.B) {
	m, sessions := benchmarkShadowManager(b, "10.200.0.0/24", 256, 128, 0)
	target := sessions[0].ShadowIP
	b.Cleanup(func() {
		for _, s := range sessions {
			s.Close()
		}
		m.CloseCleanup()
	})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = m.Lookup(target)
		}
	})
}

func BenchmarkManagerLookupUnderChurn(b *testing.B) {
	m, sessions := benchmarkShadowManager(b, "10.201.0.0/16", 256, 128, 0)
	target := sessions[0].ShadowIP
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			s := New(netip.MustParseAddr("10.200.0.2"), "churn", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
			if err := m.Register(s); err == nil {
				s.Close()
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = m.Lookup(target)
		}
	})
	b.StopTimer()
	close(stop)
	<-done
	for _, s := range sessions {
		s.Close()
	}
	m.CloseCleanup()
}

func BenchmarkManagerCoolingHeavyAllocator(b *testing.B) {
	now := time.Now()
	m := NewShadowManagerWithClock(netip.MustParsePrefix("10.202.0.0/16"), 2048, nil, time.Hour, func() time.Time { return now }, func(uint32) uint32 { return 0 })
	sessions := make([]*Session, 0, 512)
	for i := 0; i < cap(sessions); i++ {
		s := New(netip.MustParseAddr("10.200.0.2"), "cooling", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
		if err := m.Register(s); err != nil {
			b.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		s.Close()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && i%1024 == 0 {
			now = now.Add(time.Hour)
		}
		s := New(netip.MustParseAddr("10.200.0.2"), "cooling", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
		if err := m.Register(s); err != nil {
			b.Fatal(err)
		}
		m.RemoveIfCurrent(s)
	}
	b.StopTimer()
	m.CloseCleanup()
}
