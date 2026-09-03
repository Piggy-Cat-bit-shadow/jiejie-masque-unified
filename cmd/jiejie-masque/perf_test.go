package main

import (
	"bytes"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
)

func BenchmarkOutboundPacketCopy1280(b *testing.B) {
	source := bytes.Repeat([]byte{'x'}, 1280)
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
	source := bytes.Repeat([]byte{'x'}, 1280)
	pool := session.NewPacketPool(1280)
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	for b.Loop() {
		packet := pool.Get(len(source))
		copy(packet.Data, source)
		pool.Put(packet)
	}
}
