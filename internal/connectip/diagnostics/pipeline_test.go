package diagnostics

import (
	"testing"
	"time"
)

func TestProbeSnapshotRatesAndGap(t *testing.T) {
	p := &Probe{}
	p.Add(TunRead, 10, 1000)
	p.Add(SessionEnqueue, 10, 1000)
	p.Add(SessionWriterSubmit, 10, 500)
	p.ObserveWait(SessionEnqueue, 5*time.Microsecond)
	p.ObserveWait(SessionEnqueue, 100*time.Microsecond)

	s, previous := p.Snapshot(nil, time.Second)
	if got := s.Stages[string(TunRead)].Mbps; got != 0.008 {
		t.Fatalf("tun Mbps = %v", got)
	}
	if s.LargestGap.From != string(SessionEnqueue) || s.LargestGap.To != string(SessionWriterSubmit) {
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

func TestProbeJSONIsAggregateOnly(t *testing.T) {
	p := &Probe{}
	p.Add(UDPWire, 1, 1280)
	s, _ := p.Snapshot(nil, time.Second)
	b, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" || string(b) == "null" {
		t.Fatalf("empty JSON: %s", b)
	}
	for _, forbidden := range []string{"client", "destination", "payload", "private_key"} {
		if string(b) == forbidden {
			t.Fatalf("unexpected sensitive field %q", forbidden)
		}
	}
}
