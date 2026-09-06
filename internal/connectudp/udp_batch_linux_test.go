//go:build linux

package connectudp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestUDPReadBatchPreservesDatagramBoundaries(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	want := [][]byte{[]byte("one"), []byte("two-two"), bytes.Repeat([]byte{'x'}, 128), []byte("four")}
	for _, packet := range want {
		if _, err := sender.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	pool := newUDPOwnedDatagramPool()
	batch := newUDPReadBatch(receiver)
	var got [][]byte
	for len(got) < len(want) {
		n, err := batch.Read(pool)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("batch read returned no datagrams without an error")
		}
		for i := 0; i < n; i++ {
			got = append(got, bytes.Clone(batch.buffers[i].data[udpPayloadOffset:udpPayloadOffset+batch.packetLen(i)]))
		}
		batch.releaseFrom(0)
	}
	if len(got) != len(want) {
		t.Fatalf("received %d datagrams, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("datagram %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func BenchmarkUDPReadBatchLoopback(b *testing.B) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = receiver.Close() })
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = sender.Close() })

	const packetSize = 1200
	payload := bytes.Repeat([]byte{'x'}, packetSize)
	pool := newUDPOwnedDatagramPool()
	batch := newUDPReadBatch(receiver)
	b.ReportAllocs()
	b.SetBytes(packetSize)
	for b.Loop() {
		if _, err := sender.Write(payload); err != nil {
			b.Fatal(err)
		}
		n, err := batch.Read(pool)
		if err != nil {
			b.Fatal(err)
		}
		batch.releaseFrom(0)
		if n != 1 {
			b.Fatalf("received %d datagrams, want 1", n)
		}
	}
}
