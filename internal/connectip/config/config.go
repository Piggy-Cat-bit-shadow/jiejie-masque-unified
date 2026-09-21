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
	Listen      string      `yaml:"listen"`
	TLS         TLS         `yaml:"tls"`
	QUIC        QUIC        `yaml:"quic"`
	HostNetwork HostNetwork `yaml:"host_network,omitempty"`
	Client      Client      `yaml:"client"`
	Clients     []Client    `yaml:"clients,omitempty"`
	Server      Server      `yaml:"server"`
	DNSGateway  DNSGateway  `yaml:"dns_gateway,omitempty"`
}
type QUIC struct {
	StatelessResetKeyFile string `yaml:"stateless_reset_key_file"`
	CongestionController  string `yaml:"congestion_controller"`
}
type HostNetwork struct {
	ExternalInterface     string `yaml:"external_interface"`
	ExternalInterfaceIPv4 string `yaml:"external_interface_ipv4,omitempty"`
	ExternalInterfaceIPv6 string `yaml:"external_interface_ipv6,omitempty"`
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
	TunnelIPv4                string `yaml:"tunnel_ipv4"`
	TunnelIPv6                string `yaml:"tunnel_ipv6,omitempty"`
	AdvertiseIPv6DefaultRoute bool   `yaml:"advertise_ipv6_default_route,omitempty"`
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

// isUsableGlobalIPv6TunnelPrefix is deliberately conservative, not a complete
// bogon database. netip supplies semantic address classes; the small explicit
// exclusions below cover documentation, benchmarking, and discard-only
// ranges that are otherwise reported as global unicast by the standard library.
func isUsableGlobalIPv6TunnelPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return false
	}
	a := prefix.Addr()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsLoopback() || a.IsUnspecified() {
		return false
	}
	for _, reserved := range []netip.Prefix{
		netip.MustParsePrefix("100::/64"),      // Discard-only.
		netip.MustParsePrefix("2001:2::/48"),   // Benchmarking.
		netip.MustParsePrefix("2001:db8::/32"), // Documentation.
		netip.MustParsePrefix("3fff::/20"),     // Documentation.
	} {
		if prefix.Contains(reserved.Addr()) || reserved.Contains(prefix.Addr()) {
			return false
		}
	}
	return true
}

// IsUsableGlobalIPv6TunnelPrefix reports whether a prefix is semantically
// suitable for advertising routed public IPv6 egress. It is intentionally not
// a complete bogon database or proof of upstream routing.
func IsUsableGlobalIPv6TunnelPrefix(prefix netip.Prefix) bool {
	return isUsableGlobalIPv6TunnelPrefix(prefix)
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
	if c.QUIC.StatelessResetKeyFile == "" {
		c.QUIC.StatelessResetKeyFile = DefaultStatelessResetKeyFile
	}
	if c.QUIC.CongestionController == "" {
		c.QUIC.CongestionController = "cubic"
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
	if c.Listen == "" || c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("listen, tls.cert and tls.key are required")
	}
	switch c.QUIC.CongestionController {
	case "", "default", "cubic", "bbr":
	default:
		return fmt.Errorf("quic.congestion_controller must be default, cubic, or bbr")
	}
	if len(c.Clients) > 0 && (len(c.Client.PublicKeys) > 0 || c.Client.PublicKey != "" || c.Client.TunnelIPv4 != "" || c.Client.TunnelIPv6 != "") {
		return fmt.Errorf("client and clients cannot both be configured")
	}
	if c.Server.AdvertiseIPv6DefaultRoute {
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		if !addresses.IPv6.IsValid() {
			return fmt.Errorf("server.advertise_ipv6_default_route requires server.tunnel_ipv6")
		}
		if !isUsableGlobalIPv6TunnelPrefix(addresses.IPv6) {
			return fmt.Errorf("server.advertise_ipv6_default_route requires a usable global IPv6 prefix; ULA, link-local, and special-use prefixes cannot provide public egress")
		}
	}
	if _, e := c.ResolvedClients(); e != nil {
		return e
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
	return nil
}

func (d DNSGateway) IsEnabled() bool         { return d.Enabled == nil || *d.Enabled }
func mustResolved(c Config) []ResolvedClient { v, _ := c.ResolvedClients(); return v }

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
		out = append(out, ResolvedClient{Name: effectiveName, PublicKeys: keys, TunnelIPv4: v4, TunnelIPv6: v6})
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
