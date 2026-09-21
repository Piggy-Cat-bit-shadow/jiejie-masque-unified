//go:build !linux

package hostnet

import (
	"fmt"
	"net/netip"
)

func CheckIPv6Egress(string, netip.Prefix) error {
	return fmt.Errorf("IPv6 routed egress checks require Linux")
}

func usablePublicIPv6Prefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is6() && prefix.Addr().IsGlobalUnicast() && !prefix.Addr().IsPrivate()
}
