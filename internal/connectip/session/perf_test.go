package session

import (
	"context"
	"net/netip"
	"testing"
)

func BenchmarkQueueHandoff(b *testing.B) {
	for _, size := range []int{32, 64, 128, 256, 512, 1024} {
		b.Run("queue="+itoa(size), func(b *testing.B) {
			s := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.0.0.2"), "benchmark", &fakeConn{}, nil, size, nil)
			defer s.Close()
			b.ReportAllocs()
			for b.Loop() {
				p := &PacketBuffer{Data: make([]byte, 1280)}
				if !s.TryEnqueue(p) {
					<-s.Outbound
				}
			}
		})
	}
}
func itoa(v int) string {
	if v == 32 {
		return "32"
	}
	if v == 64 {
		return "64"
	}
	if v == 128 {
		return "128"
	}
	if v == 256 {
		return "256"
	}
	if v == 512 {
		return "512"
	}
	return "1024"
}
