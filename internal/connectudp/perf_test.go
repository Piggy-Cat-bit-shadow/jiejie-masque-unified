package connectudp

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

func BenchmarkBuildContextDatagram1500(b *testing.B) {
	payload := bytes.Repeat([]byte{'x'}, maxUDPPayloadSize)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet, ok := buildContextDatagram(payload)
		if !ok || len(packet) != len(contextIDZero)+len(payload) {
			b.Fatal("invalid context datagram")
		}
	}
}

func BenchmarkContextDatagramInPlace1500(b *testing.B) {
	payload := bytes.Repeat([]byte{'x'}, maxUDPPayloadSize)
	packet := make([]byte, len(contextIDZero)+len(payload))
	copy(packet, contextIDZero)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		copy(packet[len(contextIDZero):], payload)
	}
}

func BenchmarkTCPRelayCopy32KiB(b *testing.B) {
	payload := bytes.Repeat([]byte{'x'}, 32<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := io.Copy(byteSink{}, readerOnly{Reader: bytes.NewReader(payload)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPRelayCopyWithPool32KiB(b *testing.B) {
	payload := bytes.Repeat([]byte{'x'}, 32<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := copyWithPool(byteSink{}, readerOnly{Reader: bytes.NewReader(payload)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPRelayCopyWithPoolConcurrent32KiB(b *testing.B) {
	for _, workers := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("%d-connections", workers), func(b *testing.B) {
			benchmarkConcurrentRelayCopy(b, workers)
		})
	}
}

func benchmarkConcurrentRelayCopy(b *testing.B, workers int) {
	payload := bytes.Repeat([]byte{'x'}, 32<<10)
	jobs := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				if _, err := copyWithPool(byteSink{}, readerOnly{Reader: bytes.NewReader(payload)}); err != nil {
					b.Error(err)
				}
			}
		}()
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		jobs <- struct{}{}
	}
	b.StopTimer()
	close(jobs)
	wg.Wait()
}

func TestTCPRelayCopyPoolConcurrent(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, 32<<10)
	const workers = 64
	const copiesPerWorker = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range copiesPerWorker {
				if n, err := copyWithPool(byteSink{}, readerOnly{Reader: bytes.NewReader(payload)}); err != nil {
					errs <- err
					return
				} else if n != int64(len(payload)) {
					errs <- fmt.Errorf("copied %d bytes, want %d", n, len(payload))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type readerOnly struct{ io.Reader }

type byteSink struct{}

func (byteSink) Write(p []byte) (int, error) { return len(p), nil }
