package config

import (
	"net/netip"
	"testing"
)

func TestDualStackResolvedClients(t *testing.T) {
	c := Config{Server: Server{TunnelIPv4: "10.0.0.1/24", TunnelIPv6: "fd00::1/64"}, Clients: []Client{{Name: "c", PublicKey: "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M=", TunnelIPv4: "10.0.0.2/32", TunnelIPv6: "fd00::2/128"}}}
	clients, err := c.ResolvedClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || !clients[0].TunnelIPv6.IsValid() {
		t.Fatalf("resolved clients = %#v", clients)
	}
	if got := len(TunnelAddresses{IPv4: mustPrefix("10.0.0.1/24"), IPv6: mustPrefix("fd00::1/64")}.Prefixes()); got != 2 {
		t.Fatalf("prefix count=%d", got)
	}
}

func mustPrefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }
