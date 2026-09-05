package main

import (
	"fmt"
	"io"
	"net/netip"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

// networkPrepareInfo emits normalized values consumed by the privileged
// network-prepare helper. YAML parsing and validation remain in config.Load;
// the shell helper does not maintain a second YAML parser.
func networkPrepareInfo(out io.Writer, path, field string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	switch field {
	case "", "tunnel-prefix":
		prefix, err := netip.ParsePrefix(c.Server.TunnelIPv4)
		if err != nil {
			return fmt.Errorf("invalid server.tunnel_ipv4: %w", err)
		}
		_, err = fmt.Fprintln(out, prefix.String())
		return err
	case "tunnel-address":
		prefix, err := netip.ParsePrefix(c.Server.TunnelIPv4)
		if err != nil {
			return fmt.Errorf("invalid server.tunnel_ipv4: %w", err)
		}
		_, err = fmt.Fprintln(out, prefix.Addr())
		return err
	case "tunnel-network":
		prefix, err := netip.ParsePrefix(c.Server.TunnelIPv4)
		if err != nil {
			return fmt.Errorf("invalid server.tunnel_ipv4: %w", err)
		}
		_, err = fmt.Fprintln(out, prefix.Masked().String())
		return err
	case "dns-port":
		if c.DNSGateway.Enabled != nil && !*c.DNSGateway.Enabled {
			return nil
		}
		_, err := fmt.Fprintln(out, c.DNSGateway.Port)
		return err
	case "external-interface":
		if c.HostNetwork.ExternalInterface == "" {
			return nil
		}
		_, err := fmt.Fprintln(out, c.HostNetwork.ExternalInterface)
		return err
	default:
		return fmt.Errorf("unsupported network-prepare-info field %q", field)
	}
}
