package main

import (
	"bytes"
	"fmt"
	"testing"

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
