package config

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"go.yaml.in/yaml/v3"
)

type Config struct {
	Listen  string   `yaml:"listen"`
	TLS     TLS      `yaml:"tls"`
	QUIC    QUIC     `yaml:"quic"`
	Clients []Client `yaml:"clients"`
	Server  Server   `yaml:"server"`
}
type QUIC struct {
	CongestionController string `yaml:"congestion_controller"`
}
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}
type Client struct {
	PublicKey  string `yaml:"public_key"`
	TunnelIPv4 string `yaml:"tunnel_ipv4"`
	TunnelIPv6 string `yaml:"tunnel_ipv6,omitempty"`
}
type ResolvedClient struct {
	PublicKey  string
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
	if c.QUIC.CongestionController == "" {
		c.QUIC.CongestionController = "cubic"
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
	return nil
}

func mustResolved(c Config) []ResolvedClient { v, _ := c.ResolvedClients(); return v }

func (c Config) ResolvedClients() ([]ResolvedClient, error) {
	server, e := c.ServerAddresses()
	if e != nil {
		return nil, e
	}
	clients := c.Clients
	if len(clients) == 0 {
		return nil, fmt.Errorf("at least one client is required")
	}
	out := make([]ResolvedClient, 0, len(clients))
	seenIP := map[netip.Addr]bool{}
	seenKeyIP := map[string]netip.Addr{}
	for _, cl := range clients {
		v4, e := optionalPrefix(cl.TunnelIPv4, 4, "client tunnel_ipv4")
		if e != nil {
			return nil, e
		}
		if v4.IsValid() && v4.Bits() != 32 {
			return nil, fmt.Errorf("client tunnel_ipv4 must be an IPv4 /32")
		}
		v6, e := optionalPrefix(cl.TunnelIPv6, 6, "client tunnel_ipv6")
		if e != nil {
			return nil, e
		}
		if v6.IsValid() && v6.Bits() != 128 {
			return nil, fmt.Errorf("client tunnel_ipv6 must be an IPv6 /128")
		}
		if !v4.IsValid() && !v6.IsValid() {
			return nil, fmt.Errorf("client must configure tunnel_ipv4, tunnel_ipv6, or both")
		}
		if v4.IsValid() && (!server.IPv4.IsValid() || !server.IPv4.Contains(v4.Addr()) || v4.Addr() == server.IPv4.Addr()) {
			return nil, fmt.Errorf("client IPv4 tunnel IP is outside server network or equals server")
		}
		if v6.IsValid() && (!server.IPv6.IsValid() || !server.IPv6.Contains(v6.Addr()) || v6.Addr() == server.IPv6.Addr()) {
			return nil, fmt.Errorf("client IPv6 tunnel IP is outside server network or equals server")
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
		if cl.PublicKey == "" {
			return nil, fmt.Errorf("client has no public key")
		}
		if _, e = auth.ValidatePublicKeyString(cl.PublicKey); e != nil {
			return nil, fmt.Errorf("client public key: %w", e)
		}
		primary := addrOrZero(v4)
		if !primary.IsValid() {
			primary = v6.Addr()
		}
		if previous, exists := seenKeyIP[cl.PublicKey]; exists && previous != primary {
			return nil, fmt.Errorf("public key assigned to multiple tunnel IPs")
		}
		seenKeyIP[cl.PublicKey] = primary
		out = append(out, ResolvedClient{PublicKey: cl.PublicKey, TunnelIPv4: v4, TunnelIPv6: v6})
	}
	return out, nil
}

func addrOrZero(p netip.Prefix) netip.Addr {
	if p.IsValid() {
		return p.Addr()
	}
	return netip.Addr{}
}
