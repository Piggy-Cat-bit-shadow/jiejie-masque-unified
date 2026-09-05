package connectudp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTargetPolicyRejectsPrivateAndLocalAddresses(t *testing.T) {
	p := TargetPolicy{}
	for _, target := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443", "[fe80::1]:443", "[fd00::1]:443", "224.0.0.1:443", "0.0.0.0:443"} {
		if _, err := p.ResolveTarget(context.Background(), "tcp", target); err == nil {
			t.Fatalf("allowed %s", target)
		}
	}
}

func TestTargetPolicyAllowsExplicitPrivateAndPublic(t *testing.T) {
	if got, err := (TargetPolicy{AllowPrivate: true}).ResolveTarget(context.Background(), "tcp", "127.0.0.1:443"); err != nil || got != "127.0.0.1:443" {
		t.Fatalf("explicit private = %q, %v", got, err)
	}
	if got, err := (TargetPolicy{}).ResolveTarget(context.Background(), "udp", "1.1.1.1:53"); err != nil || got != "1.1.1.1:53" {
		t.Fatalf("public = %q, %v", got, err)
	}
}

func TestTargetPolicyUsesPublicGloballyReachableAddressContract(t *testing.T) {
	tests := []struct {
		address string
		allow   bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"169.254.169.254", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"240.0.0.1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
		{"192.0.0.9", true},
		{"192.0.0.10", true},
		{"192.31.196.1", true},
		{"192.52.193.1", true},
		{"192.175.48.1", true},
		{"2606:4700:4700::1111", true},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"2001:2::1", false},
		{"3fff::1", false},
		{"ff02::1", false},
		{"64:ff9b::c000:201", true},
		{"2001:1::1", true},
		{"2001:1::2", true},
		{"2001:1::3", true},
		{"2001:3::1", true},
		{"2001:4:112::1", true},
		{"2620:4f:8000::1", true},
	}
	for _, tc := range tests {
		t.Run(tc.address, func(t *testing.T) {
			_, err := (TargetPolicy{}).ResolveTarget(context.Background(), "tcp", net.JoinHostPort(tc.address, "443"))
			if (err == nil) != tc.allow {
				t.Fatalf("allow_private=false address=%s err=%v wantAllow=%t", tc.address, err, tc.allow)
			}
		})
	}
}

func TestTargetPolicyAllowPrivateOptInStillRejectsNonTargets(t *testing.T) {
	policy := TargetPolicy{AllowPrivate: true}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "fc00::1", "fe80::1"} {
		if _, err := policy.ResolveTarget(context.Background(), "tcp", net.JoinHostPort(address, "443")); err != nil {
			t.Fatalf("allow_private=true rejected %s: %v", address, err)
		}
	}
	for _, address := range []string{"0.1.2.3", "240.0.0.1", "255.255.255.255", "::", "100::1", "ff02::1"} {
		if _, err := policy.ResolveTarget(context.Background(), "tcp", net.JoinHostPort(address, "443")); err == nil {
			t.Fatalf("allow_private=true accepted non-target %s", address)
		}
	}
}

func TestTargetPolicyUnmapsIPv4MappedAddresses(t *testing.T) {
	for _, tc := range []struct {
		mapped string
		allow  bool
	}{
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:100.64.0.1", false},
		{"::ffff:198.18.0.1", false},
		{"::ffff:8.8.8.8", true},
	} {
		got, err := (TargetPolicy{}).ResolveTarget(context.Background(), "tcp", net.JoinHostPort(tc.mapped, "443"))
		if (err == nil) != tc.allow {
			t.Fatalf("mapped=%s err=%v wantAllow=%t", tc.mapped, err, tc.allow)
		}
		if tc.allow && got != "8.8.8.8:443" {
			t.Fatalf("mapped public target = %q", got)
		}
	}
}

func TestTargetPolicyFiltersMixedDNSAnswersAndDialsNumericOnce(t *testing.T) {
	lookups := 0
	var dialed string
	p := TargetPolicy{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::ffff:8.8.8.8")}, nil
		},
		dialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "udp" {
				t.Fatalf("network = %q", network)
			}
			dialed = address
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
		},
	}
	conn, err := p.DialUDP(context.Background(), "example.test:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if lookups != 1 || dialed != "8.8.8.8:53" {
		t.Fatalf("lookups=%d dialed=%q", lookups, dialed)
	}
}

func TestTargetPolicyRejectsAllDisallowedDNSAnswersWithoutLeakingThem(t *testing.T) {
	p := TargetPolicy{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil
	}}
	_, err := p.ResolveTargets(context.Background(), "internal.example.test:443")
	if err == nil || err.Error() != "target address is not allowed" {
		t.Fatalf("all-disallowed DNS error = %v", err)
	}
	if strings.Contains(err.Error(), "10.0.0.1") || strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("DNS result leaked in error: %v", err)
	}
}

func TestTargetPolicyTCPUsesOneDNSLookupAndNumericDial(t *testing.T) {
	lookups := 0
	var dialed string
	p := TargetPolicy{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8")}, nil
		},
		dialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q", network)
			}
			dialed = address
			conn, peer := net.Pipe()
			_ = peer.Close()
			return conn, nil
		},
	}
	conn, err := p.DialTCP(context.Background(), "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if lookups != 1 || dialed != "8.8.8.8:443" {
		t.Fatalf("lookups=%d dialed=%q", lookups, dialed)
	}
}

func TestTargetPolicyDNSResolutionTimeout(t *testing.T) {
	p := TargetPolicy{
		ConnectTimeout: "20ms",
		lookupNetIP: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	start := time.Now()
	_, err := p.DialUDP(context.Background(), "example.test:53")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("DNS timeout err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestTargetPolicyUDPDialTimeout(t *testing.T) {
	p := TargetPolicy{
		ConnectTimeout: "20ms",
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, err := p.DialUDP(context.Background(), "example.test:53")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("UDP timeout err=%v", err)
	}
}

func TestTargetPolicyTCPDialTimeout(t *testing.T) {
	p := TargetPolicy{
		ConnectTimeout: "20ms",
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q", network)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, err := p.DialTCP(context.Background(), "example.test:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("TCP timeout err=%v", err)
	}
}

func TestTargetPolicyFallbackSharesOneDeadline(t *testing.T) {
	p := TargetPolicy{
		ConnectTimeout: "40ms",
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		},
		dialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if address == "8.8.8.8:53" {
				time.Sleep(20 * time.Millisecond)
				return nil, errors.New("first address failed")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	start := time.Now()
	_, err := p.DialUDP(context.Background(), "example.test:53")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("fallback timeout err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestTargetPolicyParentCancellationWins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := TargetPolicy{
		ConnectTimeout: "1s",
		lookupNetIP: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	time.AfterFunc(10*time.Millisecond, cancel)
	_, err := p.DialUDP(ctx, "example.test:53")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation err=%v", err)
	}
}

func TestTargetPolicyDialUDPFallsBackInValidatedOrder(t *testing.T) {
	var attempts []string
	p := TargetPolicy{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("208.67.222.222"), netip.MustParseAddr("4.2.2.2")}, nil
		},
		dialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "udp" {
				t.Fatalf("network = %q", network)
			}
			attempts = append(attempts, address)
			if len(attempts) == 1 {
				return nil, errors.New("no route")
			}
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
		},
	}
	conn, err := p.DialUDP(context.Background(), "example.test:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(attempts) != 2 || attempts[0] != "8.8.8.8:53" || attempts[1] != "1.1.1.1:53" {
		t.Fatalf("attempts = %v", attempts)
	}
}

func TestTargetPolicyDialUDPStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	p := TargetPolicy{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			attempts++
			cancel()
			return nil, errors.New("no route")
		},
	}
	_, err := p.DialUDP(ctx, "example.test:53")
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("err=%v attempts=%d", err, attempts)
	}
}

func TestTargetPolicyDialAlreadyCanceledSkipsResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lookups := 0
	p := TargetPolicy{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return nil, errors.New("lookup should not run")
	}}
	if _, err := p.DialUDP(ctx, "example.test:53"); !errors.Is(err, context.Canceled) {
		t.Fatalf("UDP error = %v", err)
	}
	if _, err := p.DialTCP(ctx, "example.test:53"); !errors.Is(err, context.Canceled) {
		t.Fatalf("TCP error = %v", err)
	}
	if lookups != 0 {
		t.Fatalf("lookups=%d", lookups)
	}
}

func TestTargetPolicyDialUDPLimitsValidatedAddressesToFour(t *testing.T) {
	attempts := 0
	p := TargetPolicy{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("8.8.8.8"),
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("9.9.9.9"),
				netip.MustParseAddr("208.67.222.222"),
				netip.MustParseAddr("4.2.2.2"),
			}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			attempts++
			return nil, errors.New("no route")
		},
	}
	if _, err := p.DialUDP(context.Background(), "example.test:53"); err == nil {
		t.Fatal("expected dial failure")
	}
	if attempts != 4 {
		t.Fatalf("attempts=%d, want 4", attempts)
	}
}
