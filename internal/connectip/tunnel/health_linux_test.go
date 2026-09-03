//go:build linux

package tunnel

import (
	"net"
	"net/netip"
	"testing"
)

func TestNormalizeInterfacePrefix(t *testing.T) {
	mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 200, 0, 1}
	tests := []struct {
		name string
		addr net.Addr
		want netip.Prefix
		ok   bool
	}{
		{"ipv4", &net.IPNet{IP: net.IPv4(10, 200, 0, 1).To4(), Mask: net.CIDRMask(16, 32)}, netip.MustParsePrefix("10.200.0.1/16"), true},
		{"mapped-ipv4", &net.IPNet{IP: mapped, Mask: net.CIDRMask(16, 32)}, netip.MustParsePrefix("10.200.0.1/16"), true},
		{"ipv6", &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}, netip.MustParsePrefix("fe80::1/64"), true},
		{"invalid-mask", &net.IPNet{IP: net.IPv4(10, 200, 0, 1).To4(), Mask: net.IPMask{255, 0}}, netip.Prefix{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeInterfacePrefix(tt.addr)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Fatalf("normalizeInterfacePrefix() = %v, %v; want %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizedPrefixDoesNotMatchWrongIPv4(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr net.Addr
		want netip.Prefix
	}{
		{"different-address", &net.IPNet{IP: net.IPv4(10, 200, 0, 2), Mask: net.CIDRMask(16, 32)}, netip.MustParsePrefix("10.200.0.1/16")},
		{"different-prefix-length", &net.IPNet{IP: net.IPv4(10, 200, 0, 1), Mask: net.CIDRMask(24, 32)}, netip.MustParsePrefix("10.200.0.1/16")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeInterfacePrefix(tt.addr)
			if !ok || got == tt.want {
				t.Fatalf("normalized prefix unexpectedly matched: %v, %v", got, ok)
			}
		})
	}
}
