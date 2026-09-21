package main

import (
	"net/netip"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
)

type directBenchConn struct{}

func (directBenchConn) ReadPacket() ([]byte, error)        { return nil, nil }
func (directBenchConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (directBenchConn) Close() error                       { return nil }

func BenchmarkTunToConnectIPDirect(b *testing.B) {
	conn := directBenchConn{}
	mgr := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "bench", conn, nil)
	if _, err := mgr.Replace(s); err != nil {
		b.Fatal(err)
	}
	packet := make([]byte, tunnelMTU)
	packet[0], packet[2], packet[3] = 0x45, 5, 0
	copy(packet[16:20], []byte{10, 0, 0, 2})
	b.ReportAllocs()
	b.SetBytes(tunnelMTU)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dispatchTUNPacket(packet, mgr, discardTun{})
	}
}

type discardTun struct{}

func (discardTun) Write(p []byte) (int, error) { return len(p), nil }
