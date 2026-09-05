package connectudp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
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
