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
	TunnelName            string
	TunnelPrefix          netip.Prefix
	TunnelPrefixes        []netip.Prefix
	TunnelMTU             int
	ExternalInterface     string
	ExternalInterfaceIPv4 string
	ExternalInterfaceIPv6 string
	TunnelCheck           func(string, netip.Prefix, int) error
	ForwardingCheck       func() error
	NATCheck              func(string, netip.Prefix) error
	IPv6EgressCheck       func(string, netip.Prefix) error
	RequireIPv6Egress     bool
}

func (p Probe) Check() error {
	if err := p.ForwardingCheck(); err != nil {
		return fmt.Errorf("IP forwarding: %w", err)
	}
	prefixes := p.TunnelPrefixes
	if len(prefixes) == 0 {
		prefixes = []netip.Prefix{p.TunnelPrefix}
	}
	for _, prefix := range prefixes {
		family := "IPv4"
		if prefix.Addr().Is6() {
			family = "IPv6"
		}
		if err := p.TunnelCheck(p.TunnelName, prefix, p.TunnelMTU); err != nil {
			return fmt.Errorf("TUN %s (%s): %w", family, prefix, err)
		}
		if prefix.Addr().Is4() {
			iface := p.ExternalInterfaceIPv4
			if iface == "" {
				iface = p.ExternalInterface
			}
			if err := p.NATCheck(iface, prefix); err != nil {
				return fmt.Errorf("host IPv4 MASQUERADE rule (%s): %w", prefix, err)
			}
		} else if prefix.Addr().Is6() && p.RequireIPv6Egress && p.IPv6EgressCheck != nil {
			iface := p.ExternalInterfaceIPv6
			if iface == "" {
				iface = p.ExternalInterface
			}
			if err := p.IPv6EgressCheck(iface, prefix); err != nil {
				return fmt.Errorf("local IPv6 egress prerequisites (%s): %w", prefix, err)
			}
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
