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

// BenchmarkQueueControlledDrain models a writer which makes one unit of
// progress for every eight offered packets. It uses logical drain cadence
// rather than wall-clock sleeps, so results remain reproducible on CI runners.
func BenchmarkQueueControlledDrain(b *testing.B) {
	for _, size := range []int{32, 64, 128, 256, 512, 1024} {
		b.Run("queue="+itoa(size), func(b *testing.B) {
			s := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.0.0.2"), "benchmark", &fakeConn{}, nil, size, nil)
			b.ReportAllocs()
			var offered uint64
			for b.Loop() {
				offered++
				_ = s.TryEnqueue(&PacketBuffer{Data: make([]byte, 1280)})
				if offered%8 == 0 {
					select {
					case packet := <-s.Outbound:
						s.RecordDequeued()
						s.ReleasePacket(packet)
					default:
					}
				}
			}
			b.StopTimer()
			stats := s.QueueStats()
			if offered > 0 {
				b.ReportMetric(float64(stats.Dropped)*1000/float64(offered), "drops/kpkt")
			}
			b.ReportMetric(float64(stats.HighWater), "high-water")
			s.Close()
		})
	}
}

// BenchmarkQueueBurstRecovery offers a 256-packet burst then lets the writer
// completely recover before the next burst. It measures the smallest queue
// that absorbs the expected scheduling burst without carrying latency into a
// following burst.
func BenchmarkQueueBurstRecovery(b *testing.B) {
	for _, size := range []int{32, 64, 128, 256, 512, 1024} {
		b.Run("queue="+itoa(size), func(b *testing.B) {
			s := NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.0.0.2"), "benchmark", &fakeConn{}, nil, size, nil)
			b.ReportAllocs()
			for b.Loop() {
				for i := 0; i < 256; i++ {
					_ = s.TryEnqueue(&PacketBuffer{Data: make([]byte, 1280)})
				}
				for {
					select {
					case packet := <-s.Outbound:
						s.RecordDequeued()
						s.ReleasePacket(packet)
					default:
						goto drained
					}
				}
			drained:
			}
			b.StopTimer()
			stats := s.QueueStats()
			if b.N > 0 {
				b.ReportMetric(float64(stats.Dropped)/float64(b.N), "drops/burst")
			}
			b.ReportMetric(float64(stats.HighWater), "high-water")
			s.Close()
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
