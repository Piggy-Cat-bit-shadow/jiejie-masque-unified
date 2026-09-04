//go:build !linux

package tunnel

import (
	"fmt"
	"net/netip"
)

type Device struct{}

const MaxGSOBatch = 128
const MaxTXGROBatch = 32

var ErrMalformedGSO = fmt.Errorf("TUN GSO unavailable")

func Open(string, int, bool, bool) (*Device, error) {
	return nil, fmt.Errorf("TUN is supported on Linux only")
}
func (*Device) Configure(netip.Prefix) error { return fmt.Errorf("TUN unavailable") }
func (*Device) Read([]byte) (int, error)     { return 0, fmt.Errorf("TUN unavailable") }
func (*Device) Write([]byte) (int, error)    { return 0, fmt.Errorf("TUN unavailable") }
func (*Device) Close() error                 { return nil }
func (*Device) OffloadEnabled() bool         { return false }
func (*Device) TXGROEnabled() bool           { return false }
func (*Device) ReadBatch([][]byte, []int, int) (int, error) {
	return 0, fmt.Errorf("TUN unavailable")
}
func (*Device) WriteBatch([][]byte) (int, error) { return 0, fmt.Errorf("TUN unavailable") }
