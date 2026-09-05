package hostnet

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

type Probe struct {
	TunnelName        string
	TunnelPrefix      netip.Prefix
	TunnelMTU         int
	ExternalInterface string
	TunnelCheck       func(string, netip.Prefix, int) error
	ForwardingCheck   func() error
	NATCheck          func(string, netip.Prefix) error
}

func (p Probe) Check() error {
	if err := p.ForwardingCheck(); err != nil {
		return fmt.Errorf("IPv4 forwarding: %w", err)
	}
	if err := p.TunnelCheck(p.TunnelName, p.TunnelPrefix, p.TunnelMTU); err != nil {
		return fmt.Errorf("TUN: %w", err)
	}
	if err := p.NATCheck(p.ExternalInterface, p.TunnelPrefix); err != nil {
		return fmt.Errorf("host MASQUERADE rule: %w", err)
	}
	return nil
}

type Supervisor struct {
	Probe    Probe
	Interval time.Duration
}

func (s Supervisor) Run(ctx context.Context, fatal chan<- error) {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Probe.Check(); err != nil {
				failures++
				log.Printf("host-network probe failed (%d/2): %v", failures, err)
				if failures >= 2 {
					fatal <- err
					return
				}
				continue
			}
			failures = 0
		}
	}
}

func CheckNAT(external string, prefix netip.Prefix) error {
	if external == "" {
		return fmt.Errorf("external interface is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := execNft(ctx, "-a", "list", "table", "ip", "masque_lite")
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("nft query timeout")
		}
		return fmt.Errorf("nft table unavailable: %w", err)
	}
	text := string(out)
	if !strings.Contains(text, "masquerade") || !strings.Contains(text, `oifname "`+external+`"`) || !strings.Contains(text, prefix.Masked().String()) {
		return fmt.Errorf("masque_lite MASQUERADE rule missing for %s on %s", prefix.Masked(), external)
	}
	return nil
}

var execNft = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "nft", args...).CombinedOutput()
}
