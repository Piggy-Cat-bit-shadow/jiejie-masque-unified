package main

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
)

func BenchmarkOutboundPacketCopy1280(b *testing.B) {
	benchmarkOutboundPacketCopy(b, 1280)
}

func BenchmarkOutboundPacketCopy(b *testing.B) {
	for _, size := range []int{64, 512, 1280, 1500} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) { benchmarkOutboundPacketCopy(b, size) })
	}
}

func benchmarkOutboundPacketCopy(b *testing.B, size int) {
	source := bytes.Repeat([]byte{'x'}, size)
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	for b.Loop() {
		packet := append([]byte(nil), source...)
		if len(packet) != len(source) {
			b.Fatal("invalid packet copy")
		}
	}
}

func BenchmarkOutboundPacketPool1280(b *testing.B) {
	benchmarkOutboundPacketPool(b, 1280)
}

func BenchmarkOutboundPacketPool(b *testing.B) {
	for _, size := range []int{64, 512, 1280, 1500} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) { benchmarkOutboundPacketPool(b, size) })
	}
}

func benchmarkOutboundPacketPool(b *testing.B, size int) {
	source := bytes.Repeat([]byte{'x'}, size)
	pool := session.NewPacketPool(size)
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	for b.Loop() {
		packet := pool.Get(len(source))
		copy(packet.Data, source)
		pool.Put(packet)
	}
}

// BenchmarkTUNBatchSlotRefill models the common RX-offload case where a TUN
// read produces one logical packet. The old loop refilled all MaxGSOBatch
// slots; the retained-slot path refills only the transferred slot.
func BenchmarkTUNBatchSlotRefill(b *testing.B) {
	for _, retained := range []bool{false, true} {
		name := "full-refill"
		if retained {
			name = "retained-slots"
		}
		b.Run(name, func(b *testing.B) {
			pool := session.NewPacketPool(1280)
			packets := make([]*session.PacketBuffer, 128)
			bufs := make([][]byte, 128)
			sizes := make([]int, 128)
			fillTUNBatchSlots(packets, bufs, sizes, pool)
			defer releaseTUNBatchSlots(packets, pool)
			b.ReportAllocs()
			for b.Loop() {
				pool.Put(packets[0])
				packets[0] = nil
				if !retained {
					releaseTUNBatchSlots(packets, pool)
				}
				fillTUNBatchSlots(packets, bufs, sizes, pool)
			}
		})
	}
}

type sessionWriterBenchmarkConn struct{}

func (sessionWriterBenchmarkConn) ReadPacket() ([]byte, error)        { return nil, context.Canceled }
func (sessionWriterBenchmarkConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (sessionWriterBenchmarkConn) Close() error                       { return nil }

type sessionWriterOwnedBenchmarkConn struct{ sessionWriterBenchmarkConn }

func (sessionWriterOwnedBenchmarkConn) WritePacketBufferOwned([]byte, int, int, connectip.PacketPayloadOwner) ([]byte, error) {
	return nil, nil
}

// BenchmarkSessionWriterBurst isolates writer channel/select, queue stats,
// cached capability selection, and activity clock work for a ready 32-packet burst.
func BenchmarkSessionWriterBurst(b *testing.B) {
	const burst = sessionWriterDrainMax
	for _, mode := range []struct {
		name  string
		burst bool
	}{{name: "per-packet"}, {name: "ready-drain-32", burst: true}} {
		b.Run(mode.name, func(b *testing.B) {
			s := session.NewWithContextAndPacketPoolAndQueue(context.Background(), netip.MustParseAddr("10.200.0.2"), "benchmark", sessionWriterBenchmarkConn{}, nil, burst, nil)
			packets := make([]*session.PacketBuffer, burst)
			for i := range packets {
				packets[i] = writerTestPacket(byte(i))
			}
			writer := newSessionPacketWriter(s.Conn)
			batch := make([]*session.PacketBuffer, 0, burst)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for _, pkt := range packets {
					s.Outbound <- pkt
				}
				if !mode.burst {
					for range packets {
						pkt := <-s.Outbound
						s.RecordDequeued()
						_, _ = writer.write(s, pkt)
						s.Touch(time.Now())
					}
				} else {
					batch = drainSessionWriterReady(<-s.Outbound, s.Outbound, batch)
					s.RecordDequeuedN(len(batch))
					for _, pkt := range batch {
						_, _ = writer.write(s, pkt)
					}
					s.Touch(time.Now())
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*burst), "ns/packet")
			s.Close()
		})
	}
}

func BenchmarkSessionWriterCapability(b *testing.B) {
	conn := sessionWriterOwnedBenchmarkConn{}
	packet := writerTestPacket(1)
	b.Run("per-packet-assertion", func(b *testing.B) {
		for b.Loop() {
			if writer, ok := interface{}(conn).(packetBufferOwnedWriter); ok {
				_, _ = writer.WritePacketBufferOwned(packet.Buffer, session.PacketPoolHeadroom, len(packet.Data), packet)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		writer := newSessionPacketWriter(conn)
		for b.Loop() {
			_, _ = writer.owned.WritePacketBufferOwned(packet.Buffer, session.PacketPoolHeadroom, len(packet.Data), packet)
		}
	})
}
