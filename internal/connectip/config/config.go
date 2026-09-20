package config

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"go.yaml.in/yaml/v3"
)

const (
	ConnectIPStateDirectory      = "jiejie-masque-connect-ip"
	DefaultStatelessResetKeyFile = "/var/lib/" + ConnectIPStateDirectory + "/stateless-reset.key"
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
	DNSGateway  DNSGateway  `yaml:"dns_gateway,omitempty"`
	Diagnostics Diagnostics `yaml:"diagnostics,omitempty"`
}
type Diagnostics struct {
	QLog QLog `yaml:"qlog,omitempty"`
}
type QLog struct {
	Enabled   bool   `yaml:"enabled"`
	Directory string `yaml:"directory"`
}
type QUIC struct {
	StatelessResetKeyFile string `yaml:"stateless_reset_key_file"`
	CongestionController  string `yaml:"congestion_controller"`
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
	TunnelIPv6 string   `yaml:"tunnel_ipv6,omitempty"`
}
type ResolvedClient struct {
	Name       string
	PublicKeys []string
	TunnelIPv4 netip.Prefix
	TunnelIPv6 netip.Prefix
}
type Server struct {
	TunnelIPv4         string     `yaml:"tunnel_ipv4"`
	TunnelIPv6         string     `yaml:"tunnel_ipv6,omitempty"`
	MTU                int        `yaml:"mtu"`
	OutboundQueueSize  int        `yaml:"outbound_queue_size,omitempty"`
	TunOffload         bool       `yaml:"tun_offload,omitempty"`
	TunTXGRO           bool       `yaml:"tun_tx_gro,omitempty"`
	SessionIdleTimeout string     `yaml:"session_idle_timeout"`
	SessionNat         SessionNat `yaml:"session_nat,omitempty"`
}

// TunnelAddresses is the address set assigned to one CONNECT-IP endpoint.
// Prefixes are intentionally ordered IPv4 then IPv6 for stable capsule output.
type TunnelAddresses struct {
	IPv4 netip.Prefix
	IPv6 netip.Prefix
}

func (a TunnelAddresses) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, 2)
	if a.IPv4.IsValid() {
		out = append(out, a.IPv4)
	}
	if a.IPv6.IsValid() {
		out = append(out, a.IPv6)
	}
	return out
}

func (a TunnelAddresses) Addresses() []netip.Addr {
	out := make([]netip.Addr, 0, 2)
	for _, p := range a.Prefixes() {
		out = append(out, p.Addr())
	}
	return out
}

func (c Config) ServerAddresses() (TunnelAddresses, error) {
	v4, err := optionalPrefix(c.Server.TunnelIPv4, 4, "server.tunnel_ipv4")
	if err != nil {
		return TunnelAddresses{}, err
	}
	v6, err := optionalPrefix(c.Server.TunnelIPv6, 6, "server.tunnel_ipv6")
	if err != nil {
		return TunnelAddresses{}, err
	}
	if !v4.IsValid() && !v6.IsValid() {
		return TunnelAddresses{}, fmt.Errorf("at least one server tunnel address is required")
	}
	return TunnelAddresses{IPv4: v4, IPv6: v6}, nil
}

func optionalPrefix(value string, family int, field string) (netip.Prefix, error) {
	if value == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(value)
	if err != nil || !p.IsValid() || (family == 4 && (!p.Addr().Is4() || p.Bits() > 32)) || (family == 6 && (!p.Addr().Is6() || p.Bits() > 128)) {
		return netip.Prefix{}, fmt.Errorf("invalid %s", field)
	}
	a := p.Addr()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.Is4In6() || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%s uses a reserved address", field)
	}
	return p, nil
}

type SessionNat struct {
	Enabled              bool   `yaml:"enabled"`
	Pool                 string `yaml:"pool"`
	MaxSessions          int    `yaml:"max_sessions"`
	ReuseDelay           string `yaml:"reuse_delay"`
	MaxSessionsPerClient int    `yaml:"max_sessions_per_client,omitempty"`
}

// DNSGateway exposes the server's local resolver only on the CONNECT-IP
// address. It deliberately has no public listen-address option.
type DNSGateway struct {
	Enabled     *bool  `yaml:"enabled"`
	Port        int    `yaml:"port"`
	Upstream    string `yaml:"upstream"`
	Timeout     string `yaml:"timeout"`
	Concurrency int    `yaml:"concurrency"`
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
		c.QUIC.StatelessResetKeyFile = DefaultStatelessResetKeyFile
	}
	if c.QUIC.CongestionController == "" {
		c.QUIC.CongestionController = "cubic"
	}
	if c.Server.SessionIdleTimeout == "" {
		c.Server.SessionIdleTimeout = "1h"
	}
	if c.Server.OutboundQueueSize == 0 {
		c.Server.OutboundQueueSize = 1024
	}
	if c.HostNetwork.CheckInterval == "" {
		c.HostNetwork.CheckInterval = "30s"
	}
	if c.Server.SessionNat.Enabled && c.Server.SessionNat.MaxSessions == 0 {
		c.Server.SessionNat.MaxSessions = 120
	}
	if c.Server.SessionNat.Enabled && c.Server.SessionNat.ReuseDelay == "" {
		c.Server.SessionNat.ReuseDelay = "30m"
	}
	if c.Diagnostics.QLog.Enabled && c.Diagnostics.QLog.Directory == "" {
		return c, fmt.Errorf("diagnostics.qlog.directory is required when qlog is enabled")
	}
	// DNS is part of the CONNECT-IP service, rather than a client-side
	// prerequisite. Existing configurations get the production default.
	if c.DNSGateway.Enabled == nil {
		enabled := true
		c.DNSGateway.Enabled = &enabled
	}
	if c.DNSGateway.Enabled != nil && *c.DNSGateway.Enabled {
		if c.DNSGateway.Port == 0 {
			c.DNSGateway.Port = 5353
		}
		if c.DNSGateway.Upstream == "" {
			c.DNSGateway.Upstream = "127.0.0.1:53"
		}
		if c.DNSGateway.Timeout == "" {
			c.DNSGateway.Timeout = "5s"
		}
		if c.DNSGateway.Concurrency == 0 {
			c.DNSGateway.Concurrency = 32
		}
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Server.TunTXGRO && !c.Server.TunOffload {
		return fmt.Errorf("server.tun_tx_gro requires server.tun_offload=true")
	}
	if c.Mode != "" && c.Mode != "connect-ip" {
		return fmt.Errorf("mode must be connect-ip")
	}
	if c.Listen == "" || c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("listen, tls.cert and tls.key are required")
	}
	switch c.QUIC.CongestionController {
	case "", "default", "cubic":
	case "bbr":
		return fmt.Errorf("quic.congestion_controller=bbr is unavailable in this build; choose default or cubic")
	default:
		return fmt.Errorf("quic.congestion_controller must be default or cubic")
	}
	if len(c.Clients) > 0 && (len(c.Client.PublicKeys) > 0 || c.Client.PublicKey != "" || c.Client.TunnelIPv4 != "" || c.Client.TunnelIPv6 != "") {
		return fmt.Errorf("client and clients cannot both be configured")
	}
	if c.Server.MTU != 0 && (c.Server.MTU < 576 || c.Server.MTU > 65535) {
		return fmt.Errorf("server.mtu must be between 576 and 65535")
	}
	if c.Server.OutboundQueueSize != 0 && (c.Server.OutboundQueueSize < 64 || c.Server.OutboundQueueSize > 4096) {
		return fmt.Errorf("server.outbound_queue_size must be between 64 and 4096")
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
		checkInterval = "30s"
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
	if c.Server.SessionNat.MaxSessionsPerClient < 0 {
		return fmt.Errorf("server.session_nat.max_sessions_per_client must not be negative")
	}
	if c.Server.SessionNat.ReuseDelay != "" {
		if reuseDelay, e := time.ParseDuration(c.Server.SessionNat.ReuseDelay); e == nil && reuseDelay < 0 {
			return fmt.Errorf("server.session_nat.reuse_delay must not be negative")
		}
	}
	if c.DNSGateway.Enabled != nil && *c.DNSGateway.Enabled {
		if c.DNSGateway.Port < 1024 || c.DNSGateway.Port > 65535 {
			return fmt.Errorf("dns_gateway.port must be between 1024 and 65535")
		}
		if _, e := netip.ParseAddrPort(c.DNSGateway.Upstream); e != nil {
			return fmt.Errorf("invalid dns_gateway.upstream")
		}
		if d, e := time.ParseDuration(c.DNSGateway.Timeout); e != nil || d <= 0 {
			return fmt.Errorf("dns_gateway.timeout must be positive")
		}
		if c.DNSGateway.Concurrency < 1 || c.DNSGateway.Concurrency > 256 {
			return fmt.Errorf("dns_gateway.concurrency must be between 1 and 256")
		}
	}
	if c.Server.SessionNat.Enabled {
		if c.Server.TunnelIPv6 != "" {
			return fmt.Errorf("server.session_nat with IPv6 is unsupported; disable session_nat for dual-stack")
		}
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
		reuseDelay, e := time.ParseDuration(c.Server.SessionNat.ReuseDelay)
		if e != nil || c.Server.SessionNat.ReuseDelay == "" || reuseDelay < 0 {
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

func (d DNSGateway) IsEnabled() bool         { return d.Enabled == nil || *d.Enabled }
func mustResolved(c Config) []ResolvedClient { v, _ := c.ResolvedClients(); return v }

func addIPv4(a [4]byte, n uint32) [4]byte {
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v += n
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func (c Config) ResolvedClients() ([]ResolvedClient, error) {
	server, e := c.ServerAddresses()
	if e != nil {
		return nil, e
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
	seenNames := map[string]bool{}
	for i, cl := range clients {
		effectiveName := EffectiveClientName(i, cl.Name)
		if seenNames[effectiveName] {
			return nil, fmt.Errorf("duplicate client identity %q", effectiveName)
		}
		seenNames[effectiveName] = true
		v4, e := optionalPrefix(cl.TunnelIPv4, 4, fmt.Sprintf("client %q tunnel_ipv4", cl.Name))
		if e != nil {
			return nil, e
		}
		if v4.IsValid() && v4.Bits() != 32 {
			return nil, fmt.Errorf("client %q tunnel_ipv4 must be an IPv4 /32", cl.Name)
		}
		v6, e := optionalPrefix(cl.TunnelIPv6, 6, fmt.Sprintf("client %q tunnel_ipv6", cl.Name))
		if e != nil {
			return nil, e
		}
		if v6.IsValid() && v6.Bits() != 128 {
			return nil, fmt.Errorf("client %q tunnel_ipv6 must be an IPv6 /128", cl.Name)
		}
		if !v4.IsValid() && !v6.IsValid() {
			return nil, fmt.Errorf("client %q must configure tunnel_ipv4, tunnel_ipv6, or both", cl.Name)
		}
		if v4.IsValid() && (!server.IPv4.IsValid() || !server.IPv4.Contains(v4.Addr()) || v4.Addr() == server.IPv4.Addr()) {
			return nil, fmt.Errorf("client %q IPv4 tunnel IP is outside server network or equals server", cl.Name)
		}
		if v6.IsValid() && (!server.IPv6.IsValid() || !server.IPv6.Contains(v6.Addr()) || v6.Addr() == server.IPv6.Addr()) {
			return nil, fmt.Errorf("client %q IPv6 tunnel IP is outside server network or equals server", cl.Name)
		}
		for _, ip := range []netip.Addr{addrOrZero(v4), addrOrZero(v6)} {
			if !ip.IsValid() {
				continue
			}
			if seenIP[ip] {
				return nil, fmt.Errorf("duplicate client tunnel IP %s", ip)
			}
			seenIP[ip] = true
		}
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
			primary := addrOrZero(v4)
			if !primary.IsValid() {
				primary = v6.Addr()
			}
			if previous, exists := seenKeyIP[key]; exists && previous != primary {
				return nil, fmt.Errorf("public key assigned to multiple tunnel IPs")
			}
			seenKeyIP[key] = primary
		}
		out = append(out, ResolvedClient{Name: cl.Name, PublicKeys: keys, TunnelIPv4: v4, TunnelIPv6: v6})
	}
	return out, nil
}

func addrOrZero(p netip.Prefix) netip.Addr {
	if p.IsValid() {
		return p.Addr()
	}
	return netip.Addr{}
}

// EffectiveClientName is the in-memory session/quota principal for a client.
// It intentionally never derives identity from public-key material.
func EffectiveClientName(index int, configured string) string {
	if configured != "" {
		return configured
	}
	return fmt.Sprintf("client-%d", index+1)
}
