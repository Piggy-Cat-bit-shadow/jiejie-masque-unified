package main

import (
	"net/netip"
	"testing"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"github.com/metacubex/quic-go"
)

type directBenchConn struct{}

func (directBenchConn) ReadPacketBuffer() (*connectip.PacketBuffer, error) { return nil, nil }
func (directBenchConn) WritePacketBufferOwned(_ []byte, _, _ int, owner connectip.PacketPayloadOwner) ([]byte, error) {
	owner.Release()
	return nil, nil
}
func (directBenchConn) RuntimeStats() quic.RuntimeStats { return quic.RuntimeStats{} }
func (directBenchConn) Close() error                    { return nil }

func BenchmarkTunToConnectIPDirect(b *testing.B) {
	pool := session.NewPacketPool(1280)
	conn := directBenchConn{}
	mgr := session.NewManager(1)
	s := session.New(netip.MustParseAddr("10.0.0.2"), "bench", conn, nil)
	if _, err := mgr.Replace(s); err != nil {
		b.Fatal(err)
	}
	tun := &directTestTun{}
	packet := pool.Get(1280)
	packet.Data[0], packet.Data[2], packet.Data[3] = 0x45, 5, 0
	copy(packet.Data[16:20], []byte{10, 0, 0, 2})
	b.ReportAllocs()
	b.SetBytes(1280)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := pool.Get(1280)
		copy(p.Data, packet.Data)
		dispatchTUNPacket(p, mgr, pool, tun)
	}
}
