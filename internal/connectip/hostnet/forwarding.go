package hostnet

import (
	"fmt"
	"os"
	"strings"
)

var readForwarding = func() ([]byte, error) {
	return os.ReadFile("/proc/sys/net/ipv4/ip_forward")
}

func CheckIPv4Forwarding() error {
	b, err := readForwarding()
	if err != nil {
		return fmt.Errorf("read IPv4 forwarding state: %w", err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("IPv4 forwarding is disabled (set net.ipv4.ip_forward=1)")
	}
	return nil
}
