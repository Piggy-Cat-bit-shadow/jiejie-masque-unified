package config

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode        string      `yaml:"mode"`
	Listen      string      `yaml:"listen"`
	TLS         TLS         `yaml:"tls"`
	QUIC        QUIC        `yaml:"quic"`
	HostNetwork HostNetwork `yaml:"host_network,omitempty"`
	Client      Client      `yaml:"client"`
	Clients     []Client    `yaml:"clients,omitempty"`
	Server      Server      `yaml:"server"`
}
type QUIC struct {
	StatelessResetKeyFile string `yaml:"stateless_reset_key_file"`
}
type HostNetwork struct {
	ExternalInterface string `yaml:"external_interface"`
	CheckInterval     string `yaml:"check_interval"`
}
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}
type Client struct {
	Name       string   `yaml:"name,omitempty"`
	PublicKey  string   `yaml:"public_key"`
	PublicKeys []string `yaml:"public_keys"`
	TunnelIPv4 string   `yaml:"tunnel_ipv4"`
}
type ResolvedClient struct {
	Name       string
	PublicKeys []string
	TunnelIPv4 netip.Prefix
}
type Server struct {
	TunnelIPv4         string     `yaml:"tunnel_ipv4"`
	MTU                int        `yaml:"mtu"`
	SessionIdleTimeout string     `yaml:"session_idle_timeout"`
	SessionNat         SessionNat `yaml:"session_nat,omitempty"`
}
type SessionNat struct {
	Enabled              bool   `yaml:"enabled"`
	Pool                 string `yaml:"pool"`
	MaxSessions          int    `yaml:"max_sessions"`
	ReuseDelay           string `yaml:"reuse_delay"`
	MaxSessionsPerClient int    `yaml:"max_sessions_per_client,omitempty"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if e = dec.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		if e == nil {
			e = fmt.Errorf("multiple YAML documents are not allowed")
		}
		return c, e
	}
	if c.Server.MTU == 0 {
		c.Server.MTU = 1280
	}
	if c.QUIC.StatelessResetKeyFile == "" {
		c.QUIC.StatelessResetKeyFile = "/var/lib/masque-lite/stateless-reset.key"
	}
	if c.Server.SessionIdleTimeout == "" {
		c.Server.SessionIdleTimeout = "1h"
	}
	if c.HostNetwork.CheckInterval == "" {
		c.HostNetwork.CheckInterval = "10s"
	}
	if c.Server.SessionNat.Enabled && c.Server.SessionNat.MaxSessions == 0 {
		c.Server.SessionNat.MaxSessions = 120
	}
	if c.Server.SessionNat.Enabled && c.Server.SessionNat.ReuseDelay == "" {
		c.Server.SessionNat.ReuseDelay = "30m"
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Mode != "" && c.Mode != "connect-ip" {
		return fmt.Errorf("mode must be connect-ip")
	}
	if c.Listen == "" || c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("listen, tls.cert and tls.key are required")
	}
	if len(c.Clients) > 0 && (len(c.Client.PublicKeys) > 0 || c.Client.PublicKey != "" || c.Client.TunnelIPv4 != "") {
		return fmt.Errorf("client and clients cannot both be configured")
	}
	if c.Server.MTU != 0 && (c.Server.MTU < 576 || c.Server.MTU > 65535) {
		return fmt.Errorf("server.mtu must be between 576 and 65535")
	}
	idleTimeout := c.Server.SessionIdleTimeout
	if idleTimeout == "" {
		idleTimeout = "1h"
	}
	if _, e := time.ParseDuration(idleTimeout); e != nil {
		return fmt.Errorf("invalid server.session_idle_timeout")
	}
	if d, _ := time.ParseDuration(idleTimeout); d < 0 {
		return fmt.Errorf("server.session_idle_timeout must not be negative")
	}
	checkInterval := c.HostNetwork.CheckInterval
	if checkInterval == "" {
		checkInterval = "10s"
	}
	if _, e := time.ParseDuration(checkInterval); e != nil {
		return fmt.Errorf("invalid host_network.check_interval")
	}
	if d, _ := time.ParseDuration(checkInterval); d <= 0 {
		return fmt.Errorf("host_network.check_interval must be positive")
	}
	if _, e := c.ResolvedClients(); e != nil {
		return e
	}
	if c.Server.SessionNat.Enabled {
		pool, e := netip.ParsePrefix(c.Server.SessionNat.Pool)
		if e != nil || !pool.Addr().Is4() {
			return fmt.Errorf("invalid session_nat.pool")
		}
		if pool.Bits() < 16 || pool.Bits() > 30 {
			return fmt.Errorf("session_nat.pool prefix must be between /16 and /30")
		}
		server, _ := netip.ParsePrefix(c.Server.TunnelIPv4)
		poolLast := netip.AddrFrom4(addIPv4(pool.Masked().Addr().As4(), uint32((uint64(1)<<uint(32-pool.Bits()))-1)))
		if !server.Contains(pool.Masked().Addr()) || !server.Contains(poolLast) {
			return fmt.Errorf("session_nat.pool must be inside server network")
		}
		if pool.Contains(server.Addr()) {
			return fmt.Errorf("session_nat.pool must not contain server tunnel address")
		}
		if c.Server.SessionNat.MaxSessions <= 0 {
			return fmt.Errorf("session_nat.max_sessions must be positive")
		}
		if c.Server.SessionNat.MaxSessions > 4096 {
			return fmt.Errorf("session_nat.max_sessions must not exceed 4096")
		}
		if _, e := time.ParseDuration(c.Server.SessionNat.ReuseDelay); e != nil || c.Server.SessionNat.ReuseDelay == "" {
			return fmt.Errorf("invalid session_nat.reuse_delay")
		}
		available := uint64(1) << uint(32-pool.Bits())
		if available > 2 {
			available -= 2
		}
		for _, cl := range mustResolved(c) {
			if pool.Contains(cl.TunnelIPv4.Addr()) && available > 0 {
				available--
			}
		}
		if uint64(c.Server.SessionNat.MaxSessions) > available {
			return fmt.Errorf("session_nat.max_sessions exceeds available shadow addresses")
		}
	}
	return nil
}
func mustResolved(c Config) []ResolvedClient { v, _ := c.ResolvedClients(); return v }

func addIPv4(a [4]byte, n uint32) [4]byte {
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v += n
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func (c Config) ResolvedClients() ([]ResolvedClient, error) {
	server, e := netip.ParsePrefix(c.Server.TunnelIPv4)
	if e != nil || !server.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 prefix %q", c.Server.TunnelIPv4)
	}
	clients := c.Clients
	if len(clients) == 0 {
		clients = []Client{c.Client}
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("at least one client is required")
	}
	out := make([]ResolvedClient, 0, len(clients))
	seenIP := map[netip.Addr]bool{}
	seenKeyIP := map[string]netip.Addr{}
	for _, cl := range clients {
		p, e := netip.ParsePrefix(cl.TunnelIPv4)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return nil, fmt.Errorf("client %q tunnel_ipv4 must be an IPv4 /32", cl.Name)
		}
		if !server.Contains(p.Addr()) || p.Addr() == server.Addr() {
			return nil, fmt.Errorf("client %q tunnel IP is outside server network or equals server", cl.Name)
		}
		if seenIP[p.Addr()] {
			return nil, fmt.Errorf("duplicate client tunnel IP %s", p.Addr())
		}
		seenIP[p.Addr()] = true
		keys := append([]string{}, cl.PublicKeys...)
		if cl.PublicKey != "" {
			keys = append(keys, cl.PublicKey)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("client %q has no public key", cl.Name)
		}
		for _, key := range keys {
			if _, e = auth.ValidatePublicKeyString(key); e != nil {
				return nil, fmt.Errorf("client %q public key: %w", cl.Name, e)
			}
			if previous, exists := seenKeyIP[key]; exists && previous != p.Addr() {
				return nil, fmt.Errorf("public key assigned to multiple tunnel IPs")
			}
			seenKeyIP[key] = p.Addr()
		}
		out = append(out, ResolvedClient{Name: cl.Name, PublicKeys: keys, TunnelIPv4: p})
	}
	return out, nil
}
