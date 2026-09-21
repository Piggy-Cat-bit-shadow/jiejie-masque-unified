//go:build !linux

package tunnel

import (
	"fmt"
	"net/netip"
)

type Device struct{}
type Stats struct {
	RXPackets, RXBytes uint64
	TXPackets, TXBytes uint64
}

func Open(string, int) (*Device, error) {
	return nil, fmt.Errorf("TUN is supported on Linux only")
}
func (*Device) Configure(netip.Prefix) error            { return fmt.Errorf("TUN unavailable") }
func (*Device) ConfigureAddresses([]netip.Prefix) error { return fmt.Errorf("TUN unavailable") }
func (*Device) Read([]byte) (int, error)                { return 0, fmt.Errorf("TUN unavailable") }
func (*Device) Write([]byte) (int, error)               { return 0, fmt.Errorf("TUN unavailable") }
func (*Device) Close() error                            { return nil }
func (*Device) Stats() Stats                            { return Stats{} }
