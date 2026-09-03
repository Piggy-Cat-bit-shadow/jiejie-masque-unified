//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"net/netip"
)

func CheckInterface(name string, expected netip.Prefix, mtu int) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("%s missing: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s is down", name)
	}
	if iface.MTU != mtu {
		return fmt.Errorf("%s MTU mismatch: got %d want %d", name, iface.MTU, mtu)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read %s addresses: %w", name, err)
	}
	for _, addr := range addrs {
		prefix, ok := normalizeInterfacePrefix(addr)
		if !ok {
			continue
		}
		if prefix == expected || (prefix.Addr() == expected.Addr() && prefix.Bits() == expected.Bits()) {
			return nil
		}
	}
	return fmt.Errorf("%s missing address %s", name, expected)
}

// normalizeInterfacePrefix converts the platform's address representation to
// a netip prefix without allowing IPv4-mapped IPv6 values to compare as IPv6.
func normalizeInterfacePrefix(addr net.Addr) (netip.Prefix, bool) {
	var ip net.IP
	var bits int
	var maskWidth int
	switch value := addr.(type) {
	case *net.IPNet:
		ip = value.IP
		bits, maskWidth = value.Mask.Size()
		ok := maskWidth == 32 || maskWidth == 128
		if !ok {
			return netip.Prefix{}, false
		}
		// The mask width must agree with the normalized address family.
		// This also rejects non-canonical masks instead of treating them as /0.
		if bits < 0 {
			return netip.Prefix{}, false
		}
	case *net.IPAddr:
		ip = value.IP
		parsed, ok := netip.AddrFromSlice(ip)
		if !ok {
			return netip.Prefix{}, false
		}
		bits = parsed.BitLen()
	default:
		return netip.Prefix{}, false
	}

	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	parsed = parsed.Unmap()
	if parsed.Is4() {
		if bits > 32 || (maskWidth != 0 && maskWidth != 32) {
			return netip.Prefix{}, false
		}
	} else if !parsed.Is6() || bits > 128 || (maskWidth != 0 && maskWidth != 128) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(parsed, bits), true
}
