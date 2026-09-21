package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

const testClientKey = "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="

func validConfig() Config {
	return Config{Listen: "127.0.0.1:4434", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{testClientKey}, TunnelIPv4: "10.200.0.2/32"}, Server: Server{TunnelIPv4: "10.200.0.1/24"}}
}

func TestValidateAndProductionDefaults(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.QUIC.CongestionController = "cubic"
	c.QUIC.CongestionController = "reno"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown controller accepted")
	}
}

func TestLoadDefaultsAndRetiredFields(t *testing.T) {
	base := "listen: 127.0.0.1:4434\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + testClientKey + "]\n  tunnel_ipv4: 10.200.0.2/32\nserver:\n  tunnel_ipv4: 10.200.0.1/24\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.QUIC.CongestionController != "cubic" {
		t.Fatalf("unexpected lean defaults: %+v", c)
	}
	for _, field := range []string{"  outbound_queue_size: 1024\n", "  session_nat:\n    enabled: true\n", "diagnostics:\n  pipeline:\n    enabled: true\n"} {
		if err := os.WriteFile(path, []byte(base+field), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("retired field accepted: %q", field)
		}
	}
}

func TestCongestionControllerValidation(t *testing.T) {
	for _, cc := range []string{"", "default", "cubic", "bbr"} {
		c := validConfig()
		c.QUIC.CongestionController = cc
		if err := c.Validate(); err != nil {
			t.Fatalf("%q rejected: %v", cc, err)
		}
	}
}

func TestMultiClientAndDualStackValidation(t *testing.T) {
	c := validConfig()
	c.Server.TunnelIPv6 = "fd00:200::1/64"
	c.Client.TunnelIPv6 = "fd00:200::2/128"
	clients, err := c.ResolvedClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("resolved=%+v err=%v", clients, err)
	}
	if clients[0].TunnelIPv6.Addr() != netip.MustParseAddr("fd00:200::2") {
		t.Fatal("client IPv6 address lost")
	}
	c.Server.AdvertiseIPv6DefaultRoute = true
	if err := c.Validate(); err == nil {
		t.Fatal("private IPv6 prefix accepted for default route")
	}
}

func TestIPv6MTUAndPrefixValidation(t *testing.T) {
	c := validConfig()
	c.Server.TunnelIPv6 = "2001:4860:100::1/64"
	c.Client.TunnelIPv6 = "2001:4860:100::2/128"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for prefix, want := range map[string]bool{"2001:4860:100::/48": true, "fd00::/64": false, "2001:db8::/32": false, "2001:2::/48": false} {
		if got := IsUsableGlobalIPv6TunnelPrefix(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("usable(%s)=%t want %t", prefix, got, want)
		}
	}
}

func TestSessionIdleAndDNSDefaults(t *testing.T) {
	c := validConfig()
	c.DNSGateway.Enabled = nil
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
