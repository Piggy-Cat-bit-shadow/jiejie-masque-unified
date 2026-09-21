package main

import (
	"net/netip"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

func TestConnectIPRoutesByAddressFamily(t *testing.T) {
	v4 := config.TunnelAddresses{IPv4: netip.MustParsePrefix("10.200.0.2/32")}
	v6 := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::2/128")}
	server := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::1/64")}
	if got := connectIPRoutes(v4, config.TunnelAddresses{}, false); len(got) != 1 || !got[0].StartIP.Is4() {
		t.Fatalf("IPv4 routes: %+v", got)
	}
	if got := connectIPRoutes(v6, server, true); len(got) != 1 || got[0].StartIP != netip.IPv6Unspecified() {
		t.Fatalf("IPv6 routes: %+v", got)
	}
	if got := connectIPRoutes(config.TunnelAddresses{IPv4: v4.IPv4, IPv6: v6.IPv6}, server, false); len(got) != 1 {
		t.Fatalf("dual routes: %+v", got)
	}
	if got := connectIPRoutes(config.TunnelAddresses{IPv4: v4.IPv4, IPv6: v6.IPv6}, server, true); len(got) != 2 {
		t.Fatalf("dual default routes: %+v", got)
	}
}

func TestRequestTemplateRejectsMalformedAuthority(t *testing.T) {
	for _, host := range []string{"", "user@example.com", "example.com/path", "example.com:bad"} {
		if got, err := requestTemplate(host); err == nil || got != nil {
			t.Fatalf("accepted %q", host)
		}
	}
	if got, err := requestTemplate("example.com:443"); err != nil || got == nil {
		t.Fatalf("valid authority rejected: %v", err)
	}
}
