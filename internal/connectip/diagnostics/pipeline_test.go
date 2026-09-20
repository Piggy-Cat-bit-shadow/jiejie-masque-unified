package diagnostics

import (
	"strings"
	"testing"
	"time"
)

func TestProbeSnapshotRatesAndGap(t *testing.T) {
	p := &Probe{}
	p.Add(TunRead, 10, 1000)
	p.Add(SessionEnqueue, 10, 1000)
	p.Add(SessionDequeue, 10, 1000)
	p.Add(SessionWriterSubmit, 10, 500)
	p.ObserveWait(SessionEnqueue, 5*time.Microsecond)
	p.ObserveWait(SessionEnqueue, 100*time.Microsecond)

	baseline, previous := p.Snapshot(nil, time.Second)
	if !baseline.Warmup || baseline.Stages[string(TunRead)].PacketsDelta != 0 || baseline.Stages[string(TunRead)].Mbps != 0 {
		t.Fatalf("first snapshot was not a zero-rate baseline: %+v", baseline)
	}
	p.Add(TunRead, 10, 1000)
	p.Add(SessionEnqueue, 10, 1000)
	p.Add(SessionDequeue, 10, 1000)
	p.Add(SessionWriterSubmit, 10, 500)
	s, previous := p.Snapshot(previous, time.Second)
	if got := s.Stages[string(TunRead)].Mbps; got != 0.008 {
		t.Fatalf("tun Mbps = %v", got)
	}
	if s.LargestGap.From != string(SessionDequeue) || s.LargestGap.To != string(SessionWriterSubmit) {
		t.Fatalf("largest gap = %+v", s.LargestGap)
	}
	if s.Stages[string(SessionEnqueue)].WaitP99US == 0 {
		t.Fatal("wait histogram was not reported")
	}
	p.Add(TunRead, 10, 1000)
	next, _ := p.Snapshot(previous, 2*time.Second)
	if next.Stages[string(TunRead)].PacketsPerSecond != 5 {
		t.Fatalf("delta rate = %v", next.Stages[string(TunRead)].PacketsPerSecond)
	}
}

func TestProbeNeverComputesGapAcrossDirections(t *testing.T) {
	p := &Probe{}
	p.Add(UDPWire, 100, 100_000)
	p.Add(UDPRead, 1, 100)
	s, _ := p.Snapshot(nil, time.Second)
	if s.DownstreamGap.Ratio != 0 || s.UpstreamGap.Ratio != 0 || s.LargestGap.Ratio != 0 {
		t.Fatalf("invented cross-direction gap: %+v", s)
	}
}

func TestProbeJSONIsAggregateOnly(t *testing.T) {
	p := &Probe{}
	p.Add(UDPWire, 1, 1280)
	s, _ := p.Snapshot(nil, time.Second)
	s.Runtime.Scheduler.TXTurnEndedDueToRXPending.Total = 7
	s.RefreshGaps()
	b, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" || string(b) == "null" {
		t.Fatalf("empty JSON: %s", b)
	}
	for _, forbidden := range []string{"client", "destination", "payload", "private_key"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("unexpected sensitive field %q", forbidden)
		}
	}
	if !strings.Contains(string(b), `"downstream"`) || !strings.Contains(string(b), `"upstream"`) || !strings.Contains(string(b), `"scheduler"`) || !strings.Contains(string(b), `"tx_turn_ended_due_to_rx_pending":{"total":7,"delta":0}`) {
		t.Fatalf("missing typed pipeline sections: %s", b)
	}
}

func BenchmarkProbeAdd(b *testing.B) {
	b.Run("off", func(b *testing.B) {
		var p *Probe
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p.Add(QUICPacketPacked, 1, 1200)
		}
	})
	b.Run("on", func(b *testing.B) {
		p := &Probe{}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p.Add(QUICPacketPacked, 1, 1200)
		}
	})
}
