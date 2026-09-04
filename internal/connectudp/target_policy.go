package connectudp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// TargetPolicy protects the host running the proxy. Private destinations are
// denied unless an administrator explicitly enables them.
type TargetPolicy struct {
	AllowPrivate bool `yaml:"allow_private"`
}

func (p TargetPolicy) allow(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return p.AllowPrivate
	}
	if addr.Is4() && (addr.IsPrivate() || addr == netip.MustParseAddr("255.255.255.255")) {
		return p.AllowPrivate
	}
	if addr.Is6() && addr.IsPrivate() {
		return p.AllowPrivate
	}
	return true
}

// ResolveTarget resolves exactly once and returns an address that has passed
// policy checks. Dialers must use this result rather than resolving again.
func (p TargetPolicy) ResolveTarget(ctx context.Context, network, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("invalid target")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !p.allow(ip) {
			return "", fmt.Errorf("target address is not allowed")
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if p.allow(ip) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", fmt.Errorf("target address is not allowed")
}
