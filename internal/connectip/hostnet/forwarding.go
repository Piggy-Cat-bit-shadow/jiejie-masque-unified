package hostnet

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

var readForwarding = func() ([]byte, error) {
	return os.ReadFile("/proc/sys/net/ipv4/ip_forward")
}

var readIPv6Forwarding = func() ([]byte, error) {
	return os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
}

func CheckIPv4Forwarding() error {
	return checkForwardingFile("IPv4", "net.ipv4.ip_forward", readForwarding)
}

func CheckIPv6Forwarding() error {
	return checkForwardingFile("IPv6", "net.ipv6.conf.all.forwarding", readIPv6Forwarding)
}

func checkForwardingFile(family, setting string, read func() ([]byte, error)) error {
	b, err := read()
	if err != nil {
		return fmt.Errorf("read %s forwarding state: %w", family, err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("%s forwarding is disabled (set %s=1)", family, setting)
	}
	return nil
}

func CheckForwarding(prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		var err error
		if prefix.Addr().Is4() {
			err = CheckIPv4Forwarding()
		} else if prefix.Addr().Is6() {
			err = CheckIPv6Forwarding()
		}
		if err != nil {
			return err
		}
	}
	return nil
}
