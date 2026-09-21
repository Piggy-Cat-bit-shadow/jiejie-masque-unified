package main

import (
	"fmt"
	"io"

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
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := firstPrefix(addresses)
		_, err = fmt.Fprintln(out, prefix.String())
		return err
	case "tunnel-prefixes":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		for _, prefix := range addresses.Prefixes() {
			if _, err = fmt.Fprintln(out, prefix.String()); err != nil {
				return err
			}
		}
		return nil
	case "tunnel-ipv4-prefix", "tunnel-ipv6-prefix":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := addresses.IPv4
		if field == "tunnel-ipv6-prefix" {
			prefix = addresses.IPv6
		}
		if !prefix.IsValid() {
			return nil
		}
		_, err = fmt.Fprintln(out, prefix.String())
		return err
	case "tunnel-ipv4-address", "tunnel-ipv6-address":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := addresses.IPv4
		if field == "tunnel-ipv6-address" {
			prefix = addresses.IPv6
		}
		if !prefix.IsValid() {
			return nil
		}
		_, err = fmt.Fprintln(out, prefix.Addr())
		return err
	case "tunnel-ipv4-network", "tunnel-ipv6-network":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := addresses.IPv4
		if field == "tunnel-ipv6-network" {
			prefix = addresses.IPv6
		}
		if !prefix.IsValid() {
			return nil
		}
		_, err = fmt.Fprintln(out, prefix.Masked())
		return err
	case "tunnel-addresses":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		for _, address := range addresses.Addresses() {
			if _, err = fmt.Fprintln(out, address); err != nil {
				return err
			}
		}
		return nil
	case "tunnel-address":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := firstPrefix(addresses)
		_, err = fmt.Fprintln(out, prefix.Addr())
		return err
	case "tunnel-network":
		addresses, err := c.ServerAddresses()
		if err != nil {
			return err
		}
		prefix := firstPrefix(addresses)
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
	case "external-interface-ipv4":
		value := c.HostNetwork.ExternalInterfaceIPv4
		if value == "" {
			value = c.HostNetwork.ExternalInterface
		}
		if value == "" {
			return nil
		}
		_, err := fmt.Fprintln(out, value)
		return err
	case "external-interface-ipv6":
		value := c.HostNetwork.ExternalInterfaceIPv6
		if value == "" {
			value = c.HostNetwork.ExternalInterface
		}
		if value == "" {
			return nil
		}
		_, err := fmt.Fprintln(out, value)
		return err
	case "advertise-ipv6-default-route":
		_, err := fmt.Fprintln(out, c.Server.AdvertiseIPv6DefaultRoute)
		return err
	default:
		return fmt.Errorf("unsupported network-prepare-info field %q", field)
	}
}
