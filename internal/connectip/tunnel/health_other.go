//go:build !linux

package tunnel

import (
	"fmt"
	"net/netip"
)

func CheckInterface(name string, expected netip.Prefix, mtu int) error {
	return fmt.Errorf("TUN health checks require Linux")
}
