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
	TunnelPrefixes    []netip.Prefix
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
	prefixes := p.TunnelPrefixes
	if len(prefixes) == 0 {
		prefixes = []netip.Prefix{p.TunnelPrefix}
	}
	for _, prefix := range prefixes {
		if err := p.NATCheck(p.ExternalInterface, prefix); err != nil {
			return fmt.Errorf("host MASQUERADE rule (%s): %w", prefix, err)
		}
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
	if prefix.Addr().Is6() {
		// IPv6 is routed by default. NAT66 is an explicit future mode, not a
		// prerequisite for a production dual-stack deployment.
		return nil
	}
	if external == "" {
		return fmt.Errorf("external interface is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	family := "ip"
	if prefix.Addr().Is6() {
		family = "ip6"
	}
	out, err := execNft(ctx, "-a", "list", "table", family, "masque_lite")
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
