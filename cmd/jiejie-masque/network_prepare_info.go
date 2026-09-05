package main

import (
	"fmt"
	"io"
	"net/netip"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

// networkPrepareInfo emits the one normalized value consumed by the
// privileged network-prepare helper. YAML parsing and validation remain in
// config.Load; the shell helper does not maintain a second YAML parser.
func networkPrepareInfo(out io.Writer, path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(c.Server.TunnelIPv4)
	if err != nil {
		return fmt.Errorf("invalid server.tunnel_ipv4: %w", err)
	}
	_, err = fmt.Fprintln(out, prefix.String())
	return err
}
