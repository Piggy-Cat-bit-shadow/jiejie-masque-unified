//go:build linux

package hostnet

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseIPv4DefaultRouteFixtures(t *testing.T) {
	const header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT"
	if got, err := parseIPv4DefaultRoute(strings.NewReader(header + "\neth9 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n")); err != nil || got != "eth9" {
		t.Fatalf("v4 route = %q, %v", got, err)
	}
	if _, err := parseIPv4DefaultRoute(strings.NewReader(header + "\nmalformed\n")); err == nil {
		t.Fatal("malformed v4 route was accepted")
	}
}

func TestUsablePublicIPv6Prefix(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   bool
	}{
		{"2001:4860:100::/48", true},
		{"fd00:200::/64", false},
		{"2001:db8::/32", false},
		{"fe80::/64", false},
		{"::/0", false},
	} {
		if got := usablePublicIPv6Prefix(netip.MustParsePrefix(tc.prefix)); got != tc.want {
			t.Errorf("usablePublicIPv6Prefix(%s) = %t, want %t", tc.prefix, got, tc.want)
		}
	}
}

func TestParseIPv6DefaultRouteFixtures(t *testing.T) {
	zero := strings.Repeat("0", 32)
	line := zero + " 00 " + zero + " 00 00000000 0000000a 00000000 00000000 00000001 eth6\n"
	if got, err := parseIPv6DefaultRoute(strings.NewReader(line)); err != nil || got != "eth6" {
		t.Fatalf("v6 route = %q, %v", got, err)
	}
	if _, err := parseIPv6DefaultRoute(strings.NewReader("bad\n")); err == nil {
		t.Fatal("malformed v6 route was accepted")
	}
}

func TestParseIPv6DefaultRouteChoosesLowestUsableMetric(t *testing.T) {
	zero := strings.Repeat("0", 32)
	route := func(metric, flags, iface string) string {
		return zero + " 00 " + zero + " 00 00000000 " + metric + " 00000000 00000000 " + flags + " " + iface + "\n"
	}
	input := route("00000001", "00000000", "dead0") + // Not UP.
		route("00000000", "00000201", "reject0") + // RTF_REJECT despite RTF_UP.
		route("00000020", "00000001", "eth20") +
		route("00000005", "00000001", "eth5") +
		route("malformed", "00000001", "bad0")
	if got, err := parseIPv6DefaultRoute(strings.NewReader(input)); err != nil || got != "eth5" {
		t.Fatalf("selected IPv6 default route = %q, %v; want eth5", got, err)
	}
	if _, err := parseIPv6DefaultRoute(strings.NewReader(route("00000001", "00000000", "down0"))); err == nil {
		t.Fatal("route without RTF_UP was accepted")
	}
}
