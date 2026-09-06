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
	var retained *udpOwnedDatagram
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
			batch.buffers[i].Release()
			batch.buffers[i] = nil
		}
		if retained == nil && n < udpReadBatchSize {
			retained = batch.buffers[n]
		}
	}
	batch.releaseAll()
	if len(got) != len(want) {
		t.Fatalf("received %d datagrams, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("datagram %d = %q, want %q", i, got[i], want[i])
		}
	}
	if retained == nil {
		t.Fatal("batch did not retain an unused buffer slot")
	}
}

func TestUDPWriteBatchPreservesDatagramBoundaries(t *testing.T) {
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
	payloads := [][]byte{[]byte("one"), []byte("two-two"), {}, bytes.Repeat([]byte{'x'}, 128)}
	writer := newUDPWriteBatch(sender)
	if n, err := writer.Write(payloads); err != nil || n != len(payloads) {
		t.Fatalf("Write batch = %d, %v", n, err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i, want := range payloads {
		buf := make([]byte, 256)
		n, _, err := receiver.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d = %q, want %q", i, buf[:n], want)
		}
	}
}

func BenchmarkUDPReadBatchLoopback(b *testing.B) {
	b.Run("single-read", benchmarkUDPReadSingleLoopback)
	for _, retained := range []bool{false, true} {
		name := "full-refill"
		if retained {
			name = "retained-slots"
		}
		b.Run(name, func(b *testing.B) { benchmarkUDPReadBatchLoopback(b, retained) })
	}
}

func benchmarkUDPReadSingleLoopback(b *testing.B) {
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
	payload := bytes.Repeat([]byte{'x'}, 1200)
	buf := make([]byte, len(payload)+1)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := sender.Write(payload); err != nil {
			b.Fatal(err)
		}
		if n, err := receiver.Read(buf); err != nil || n != len(payload) {
			b.Fatalf("single read = %d, %v", n, err)
		}
	}
}

func benchmarkUDPReadBatchLoopback(b *testing.B, retained bool) {
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
		if retained {
			for i := 0; i < n; i++ {
				batch.buffers[i].Release()
				batch.buffers[i] = nil
			}
		} else {
			batch.releaseAll()
		}
		if n != 1 {
			b.Fatalf("received %d datagrams, want 1", n)
		}
	}
}
