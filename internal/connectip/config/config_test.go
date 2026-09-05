package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	c := Config{Listen: "127.0.0.1:4434", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{"BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="}, TunnelIPv4: "10.200.0.2/32"}, Server: Server{TunnelIPv4: "10.200.0.1/30"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Server.TunTXGRO = true
	if e := c.Validate(); e == nil || e.Error() != "server.tun_tx_gro requires server.tun_offload=true" {
		t.Fatalf("invalid TX GRO config error = %v", e)
	}
	c.Server.TunOffload = true
	if e := c.Validate(); e != nil {
		t.Fatalf("valid TX GRO config: %v", e)
	}
	c.Server.TunnelIPv4 = "::1/128"
	if e := c.Validate(); e == nil {
		t.Fatal("expected IPv6 rejection")
	}
}

func TestLoadSessionIdleTimeoutDefaultAndDisable(t *testing.T) {
	key := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	base := "listen: 127.0.0.1:4434\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + key + "]\n  tunnel_ipv4: 10.200.0.2/32\nserver:\n  tunnel_ipv4: 10.200.0.1/30\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.SessionIdleTimeout != "1h" {
		t.Fatalf("default idle timeout = %q", c.Server.SessionIdleTimeout)
	}
	if c.Server.OutboundQueueSize != 256 {
		t.Fatalf("default outbound queue size = %d", c.Server.OutboundQueueSize)
	}
	if c.Server.TunOffload {
		t.Fatal("TUN offload must default to disabled")
	}
	if c.QUIC.CongestionController != "default" {
		t.Fatalf("default congestion controller = %q", c.QUIC.CongestionController)
	}
	if err := os.WriteFile(path, []byte(base+"  session_idle_timeout: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.SessionIdleTimeout != "0" {
		t.Fatalf("disabled idle timeout = %q", c.Server.SessionIdleTimeout)
	}
	if c.HostNetwork.CheckInterval != "30s" {
		t.Fatalf("default check interval = %q", c.HostNetwork.CheckInterval)
	}
}

func TestLoadAppliesSessionAndDNSDefaultsBeforeValidation(t *testing.T) {
	key := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "listen: 127.0.0.1:4434\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + key + "]\n  tunnel_ipv4: 10.200.0.2/32\nserver:\n  tunnel_ipv4: 10.200.0.1/24\n  session_nat:\n    enabled: true\n    pool: 10.200.0.128/25\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.MTU != 1280 || c.Server.OutboundQueueSize != 256 {
		t.Fatalf("server defaults = mtu %d queue %d", c.Server.MTU, c.Server.OutboundQueueSize)
	}
	if c.Server.SessionNat.MaxSessions != 120 || c.Server.SessionNat.ReuseDelay != "30m" {
		t.Fatalf("session NAT defaults = max %d delay %q", c.Server.SessionNat.MaxSessions, c.Server.SessionNat.ReuseDelay)
	}
	if c.DNSGateway.Enabled == nil || !*c.DNSGateway.Enabled || c.DNSGateway.Port != 5353 || c.DNSGateway.Upstream != "127.0.0.1:53" || c.DNSGateway.Timeout != "5s" || c.DNSGateway.Concurrency != 32 {
		t.Fatalf("DNS defaults = %+v", c.DNSGateway)
	}
}

func TestLoadTunOffload(t *testing.T) {
	key := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "listen: 127.0.0.1:4434\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + key + "]\n  tunnel_ipv4: 10.200.0.2/32\nserver:\n  tunnel_ipv4: 10.200.0.1/30\n  tun_offload: true\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Server.TunOffload {
		t.Fatal("tun_offload: true was not loaded")
	}
}

func TestCongestionControllerValidation(t *testing.T) {
	c := Config{Listen: "127.0.0.1:4434", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{"BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="}, TunnelIPv4: "10.200.0.2/32"}, Server: Server{TunnelIPv4: "10.200.0.1/30"}}
	c.QUIC.CongestionController = "cubic"
	if err := c.Validate(); err != nil {
		t.Fatalf("cubic rejected: %v", err)
	}
	c.QUIC.CongestionController = "bbr"
	if err := c.Validate(); err == nil {
		t.Fatal("expected unsupported BBR to be rejected")
	}
	c.QUIC.CongestionController = "reno"
	if err := c.Validate(); err == nil {
		t.Fatal("expected unknown controller to be rejected")
	}
}

func TestMultiClientValidation(t *testing.T) {
	keyA := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	keyB := "BJVHqCpze4DJd2ZMvQDENmffhP3y1iW9t63vgbGvZ2mCC9kAmupPlruK5JYN8ZpAOFBTQ9zetFSFbPIBH3mWbgA="
	c := Config{Listen: "127.0.0.1:4434", TLS: TLS{Cert: "c", Key: "k"}, Clients: []Client{{Name: "iphone", PublicKeys: []string{keyA}, TunnelIPv4: "10.200.0.2/32"}, {Name: "mac", PublicKeys: []string{keyB}, TunnelIPv4: "10.200.0.3/32"}}, Server: Server{TunnelIPv4: "10.200.0.1/24", MTU: 1280}}
	clients, err := c.ResolvedClients()
	if err != nil || len(clients) != 2 {
		t.Fatalf("clients = %#v, err = %v", clients, err)
	}
	c.Clients[1].TunnelIPv4 = "10.90.0.3/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected client outside server subnet to fail")
	}
	c.Clients[1].TunnelIPv4 = "10.200.0.2/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected duplicate IP to fail")
	}
	c.Clients[1].TunnelIPv4 = "10.200.0.3/32"
	c.Clients[1].PublicKeys = []string{keyA}
	c.Clients[1].TunnelIPv4 = "10.200.0.4/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected duplicate key to fail")
	}
}

func TestEffectiveClientIdentityValidation(t *testing.T) {
	keyA := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	keyB := "BJVHqCpze4DJd2ZMvQDENmffhP3y1iW9t63vgbGvZ2mCC9kAmupPlruK5JYN8ZpAOFBTQ9zetFSFbPIBH3mWbgA="
	base := Config{Listen: "127.0.0.1:4434", TLS: TLS{Cert: "c", Key: "k"}, Server: Server{TunnelIPv4: "10.200.0.1/24"}}

	duplicate := base
	duplicate.Clients = []Client{{Name: "phone", PublicKeys: []string{keyA}, TunnelIPv4: "10.200.0.2/32"}, {Name: "phone", PublicKeys: []string{keyB}, TunnelIPv4: "10.200.0.3/32"}}
	if _, err := duplicate.ResolvedClients(); err == nil {
		t.Fatal("duplicate explicit client names were accepted")
	}

	generatedCollision := base
	generatedCollision.Clients = []Client{{PublicKeys: []string{keyA}, TunnelIPv4: "10.200.0.2/32"}, {Name: "client-1", PublicKeys: []string{keyB}, TunnelIPv4: "10.200.0.3/32"}}
	if _, err := generatedCollision.ResolvedClients(); err == nil {
		t.Fatal("blank client name colliding with generated identity was accepted")
	}

	twoUnnamed := base
	twoUnnamed.Clients = []Client{{PublicKeys: []string{keyA}, TunnelIPv4: "10.200.0.2/32"}, {PublicKeys: []string{keyB}, TunnelIPv4: "10.200.0.3/32"}}
	if _, err := twoUnnamed.ResolvedClients(); err != nil {
		t.Fatalf("unnamed clients were rejected: %v", err)
	}
	if got := EffectiveClientName(0, ""); got != "client-1" {
		t.Fatalf("generated identity = %q", got)
	}
	if got := EffectiveClientName(1, ""); got != "client-2" {
		t.Fatalf("generated identity = %q", got)
	}

	negativePerClient := base
	negativePerClient.Server.SessionNat = SessionNat{MaxSessionsPerClient: -1}
	if err := negativePerClient.Validate(); err == nil {
		t.Fatal("negative max_sessions_per_client was accepted")
	}

	sessionBase := base
	sessionBase.Client = Client{PublicKeys: []string{keyA}, TunnelIPv4: "10.200.0.2/32"}
	sessionBase.Server.SessionNat = SessionNat{Enabled: true, Pool: "10.200.0.128/25", MaxSessions: 120, ReuseDelay: "30m"}
	for _, tc := range []struct {
		name       string
		perClient  int
		reuseDelay string
		wantError  bool
	}{
		{name: "zero values", perClient: 0, reuseDelay: "0s"},
		{name: "positive values", perClient: 2, reuseDelay: "1s"},
		{name: "negative per-client limit", perClient: -1, reuseDelay: "0s", wantError: true},
		{name: "negative reuse delay", perClient: 0, reuseDelay: "-1s", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sessionBase
			c.Server.SessionNat.MaxSessionsPerClient = tc.perClient
			c.Server.SessionNat.ReuseDelay = tc.reuseDelay
			if err := c.Validate(); (err != nil) != tc.wantError {
				t.Fatalf("Validate() error = %v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestSessionNatValidation(t *testing.T) {
	key := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	c := Config{
		Listen: "127.0.0.1:4434",
		TLS:    TLS{Cert: "c", Key: "k"},
		Client: Client{PublicKeys: []string{key}, TunnelIPv4: "10.200.0.2/32"},
		Server: Server{TunnelIPv4: "10.200.0.1/24", SessionNat: SessionNat{Enabled: true, Pool: "10.200.0.128/25", MaxSessions: 120, ReuseDelay: "30m"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Server.SessionNat.Pool = "10.200.0.0/25"
	if err := c.Validate(); err == nil {
		t.Fatal("expected pool containing server address to fail")
	}
}
