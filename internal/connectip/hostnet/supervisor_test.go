package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func healthyProbe() Probe {
	return Probe{
		TunnelName: "masque0", TunnelPrefix: netip.MustParsePrefix("10.200.0.1/30"), TunnelMTU: 1280,
		ExternalInterface: "eth0",
		TunnelCheck:       func(string, netip.Prefix, int) error { return nil },
		ForwardingCheck:   func() error { return nil },
		NATCheck:          func(string, netip.Prefix) error { return nil },
	}
}

func TestProbeChecksAllDataPlaneInvariants(t *testing.T) {
	checks := []string{"forwarding", "tun", "nat"}
	for _, tc := range checks {
		t.Run(tc, func(t *testing.T) {
			q := healthyProbe()
			switch tc {
			case "forwarding":
				q.ForwardingCheck = func() error { return errors.New("off") }
			case "tun":
				q.TunnelCheck = func(string, netip.Prefix, int) error { return errors.New("down") }
			case "nat":
				q.NATCheck = func(string, netip.Prefix) error { return errors.New("missing") }
			}
			if err := q.Check(); err == nil {
				t.Fatal("expected invariant failure")
			}
		})
	}
}

func TestSupervisorRequiresTwoConsecutiveFailures(t *testing.T) {
	p := healthyProbe()
	var unhealthy atomic.Bool
	p.NATCheck = func(string, netip.Prefix) error {
		if unhealthy.Load() {
			return errors.New("missing")
		}
		return nil
	}
	unhealthy.Store(true)
	fatal := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (Supervisor{Probe: p, Interval: time.Millisecond}).Run(ctx, fatal)
	select {
	case err := <-fatal:
		if err == nil {
			t.Fatal("fatal error is nil")
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not fail after two checks")
	}
}

func TestCheckNATOutput(t *testing.T) {
	old := execNft
	defer func() { execNft = old }()
	execNft = func(context.Context, ...string) ([]byte, error) {
		return []byte(`table ip masque_lite { chain postrouting { oifname "eth0" ip saddr 10.200.0.0/16 masquerade } }`), nil
	}
	if err := CheckNAT("eth0", netip.MustParsePrefix("10.200.0.1/16")); err != nil {
		t.Fatal(err)
	}
}
