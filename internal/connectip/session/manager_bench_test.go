package session

import (
	"context"
	"net/netip"
	"testing"
)

type lookupBenchConn struct{}

func (lookupBenchConn) ReadPacket() ([]byte, error)        { return nil, nil }
func (lookupBenchConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (lookupBenchConn) Close() error                       { return nil }

func BenchmarkManagerLookup(b *testing.B) {
	m := NewManager()
	for i := 2; i < 250; i++ {
		s := New(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), "bench", lookupBenchConn{}, nil)
		if _, err := m.Replace(s); err != nil {
			b.Fatal(err)
		}
	}
	ip := netip.MustParseAddr("10.0.0.2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Lookup(ip)
	}
}

func BenchmarkTunToConnectIPDirect(b *testing.B) {
	m := NewManager()
	ip := netip.MustParseAddr("10.10.0.2")
	s := NewWithContext(context.Background(), ip, "benchmark", lookupBenchConn{}, nil)
	if _, err := m.Replace(s); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(1280)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m.Lookup(ip) == nil {
			b.Fatal("session lookup miss")
		}
	}
}
