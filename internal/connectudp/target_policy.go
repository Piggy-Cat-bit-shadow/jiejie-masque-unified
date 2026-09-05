package connectudp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// TargetPolicy protects the host running the proxy. Private destinations are
// denied unless an administrator explicitly enables them.
type TargetPolicy struct {
	AllowPrivate bool `yaml:"allow_private"`
	lookupNetIP  func(context.Context, string, string) ([]netip.Addr, error)
	dialContext  func(context.Context, string, string) (net.Conn, error)
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
func (p TargetPolicy) ResolveTargets(ctx context.Context, target string) ([]string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid target")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c net.Conn
		e error
	}
	results := make(chan result, len(addresses))
	var wg sync.WaitGroup
	for _, address := range addresses {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			c, e := (&net.Dialer{}).DialContext(ctx, "tcp", a)
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
