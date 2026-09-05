package connectudp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const defaultTargetConnectTimeout = 10 * time.Second

// These tables are a static snapshot checked against the IANA IPv4/IPv6
// Special-Purpose Address Registries (last updated 2025-10-09). The policy
// follows each entry's Globally Reachable meaning, including more-specific
// globally reachable exceptions inside broader non-global prefixes.
var (
	publicIPv4Exceptions = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.9/32"),
		netip.MustParsePrefix("192.0.0.10/32"),
		netip.MustParsePrefix("192.31.196.0/24"),
		netip.MustParsePrefix("192.52.193.0/24"),
		netip.MustParsePrefix("192.175.48.0/24"),
	}
	nonGlobalIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	publicIPv6Exceptions = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("2001:1::1/128"),
		netip.MustParsePrefix("2001:1::2/128"),
		netip.MustParsePrefix("2001:1::3/128"),
		netip.MustParsePrefix("2001:3::/32"),
		netip.MustParsePrefix("2001:4:112::/48"),
		netip.MustParsePrefix("2001:20::/28"),
		netip.MustParsePrefix("2001:30::/28"),
		netip.MustParsePrefix("2620:4f:8000::/48"),
	}
	nonGlobalIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("100:0:0:1::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:10::/28"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
)

// TargetPolicy protects the host running the proxy. With AllowPrivate false,
// only public globally reachable unicast destinations are accepted.
type TargetPolicy struct {
	AllowPrivate   bool   `yaml:"allow_private"`
	ConnectTimeout string `yaml:"connect_timeout,omitempty"`
	lookupNetIP    func(context.Context, string, string) ([]netip.Addr, error)
	dialContext    func(context.Context, string, string) (net.Conn, error)
}

func (p TargetPolicy) allow(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || isNeverTarget(addr) {
		return false
	}
	if p.AllowPrivate {
		return true
	}
	return isPublicInternetDestination(addr)
}

func isNeverTarget(addr netip.Addr) bool {
	if addr.Is4() {
		return matchesPrefix(addr, netip.MustParsePrefix("0.0.0.0/8")) ||
			matchesPrefix(addr, netip.MustParsePrefix("240.0.0.0/4")) ||
			addr == netip.MustParseAddr("255.255.255.255")
	}
	// Discard-only and dummy IPv6 blocks are not meaningful connected targets,
	// even when an administrator opts into private/special destinations.
	return matchesPrefix(addr, netip.MustParsePrefix("100::/64")) ||
		matchesPrefix(addr, netip.MustParsePrefix("100:0:0:1::/64"))
}

func isPublicInternetDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || isNeverTarget(addr) {
		return false
	}
	if addr.Is4() {
		if matchesAnyPrefix(addr, publicIPv4Exceptions) {
			return true
		}
		if matchesAnyPrefix(addr, nonGlobalIPv4Prefixes) {
			return false
		}
	} else if addr.Is6() {
		if matchesAnyPrefix(addr, publicIPv6Exceptions) {
			return true
		}
		if matchesAnyPrefix(addr, nonGlobalIPv6Prefixes) {
			return false
		}
	}
	return addr.IsGlobalUnicast()
}

func matchesAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func matchesPrefix(addr netip.Addr, prefix netip.Prefix) bool {
	return prefix.Contains(addr)
}

func (p TargetPolicy) ConnectTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(p.ConnectTimeout)
	if err != nil || d <= 0 {
		return defaultTargetConnectTimeout
	}
	return d
}

func (p TargetPolicy) establishmentContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.ConnectTimeoutDuration())
}

// ResolveTarget resolves exactly once and returns an address that has passed
// policy checks. Dialers must use this result rather than resolving again.
func (p TargetPolicy) ResolveTargets(ctx context.Context, target string) ([]string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid target")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !p.allow(ip) {
			return nil, fmt.Errorf("target address is not allowed")
		}
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	lookup := p.lookupNetIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if p.allow(ip) {
			allowed = append(allowed, net.JoinHostPort(ip.String(), port))
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("target address is not allowed")
	}
	return allowed, nil
}

func (p TargetPolicy) ResolveTarget(ctx context.Context, network, target string) (string, error) {
	a, e := p.ResolveTargets(ctx, target)
	if e != nil {
		return "", e
	}
	return a[0], nil
}

// DialTCP races at most four already-validated addresses. No hostname reaches
// net.Dialer, preserving exactly-once DNS resolution and policy enforcement.
func (p TargetPolicy) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := p.establishmentContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err := p.ResolveTargets(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(addresses) > 4 {
		addresses = addresses[:4]
	}
	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()
	type result struct {
		c net.Conn
		e error
	}
	results := make(chan result, len(addresses))
	dial := p.dialContext
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	var wg sync.WaitGroup
	for _, address := range addresses {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			c, e := dial(dialCtx, "tcp", a)
			results <- result{c, e}
		}(address)
	}
	go func() { wg.Wait(); close(results) }()
	var last error
	for r := range results {
		if r.e == nil {
			go func() {
				for other := range results {
					if other.c != nil {
						_ = other.c.Close()
					}
				}
			}()
			return r.c, nil
		}
		last = r.e
	}
	return nil, last
}

// DialUDP resolves exactly once, validates every result, and then tries at
// most four validated numeric addresses in resolver order. It deliberately
// does not race UDP dials: a successful UDP connect does not prove reachability.
func (p TargetPolicy) DialUDP(ctx context.Context, target string) (*net.UDPConn, error) {
	ctx, cancel := p.establishmentContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err := p.ResolveTargets(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(addresses) > 4 {
		addresses = addresses[:4]
	}
	dial := p.dialContext
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	var last error
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, "udp", address)
		if err == nil {
			udpConn, ok := conn.(*net.UDPConn)
			if !ok {
				_ = conn.Close()
				return nil, fmt.Errorf("UDP dial returned %T", conn)
			}
			return udpConn, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
