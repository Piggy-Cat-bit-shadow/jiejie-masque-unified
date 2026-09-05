package connectudp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/quicvarint"
)

func TestContextDatagram(t *testing.T) {
	p, ok, e := parseContextDatagram(quicvarint.Append([]byte{}, 0))
	if e != nil || !ok || len(p) != 0 {
		t.Fatal("empty context 0")
	}
	p, ok, e = parseContextDatagram(quicvarint.Append([]byte{}, 1))
	if e != nil || ok || p != nil {
		t.Fatal("nonzero context")
	}
	if _, _, e = parseContextDatagram([]byte{0xff}); e == nil {
		t.Fatal("malformed varint")
	}
	if _, ok := buildContextDatagram(bytes.Repeat([]byte{'x'}, 1500)); !ok {
		t.Fatal("1500 should pass")
	}
	if _, ok := buildContextDatagram(bytes.Repeat([]byte{'x'}, 1501)); ok {
		t.Fatal("1501 should drop")
	}
}

type testDatagramSender struct{ errs []error }

func (s *testDatagramSender) SendDatagram([]byte) error {
	err := s.errs[0]
	s.errs = s.errs[1:]
	return err
}

func TestOversizedDatagramDoesNotEndFlow(t *testing.T) {
	sender := &testDatagramSender{errs: []error{&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}, nil}}
	if err := sendDatagramOrDrop(sender, []byte("oversized")); err != nil {
		t.Fatal(err)
	}
	if err := sendDatagramOrDrop(sender, []byte("valid")); err != nil {
		t.Fatal(err)
	}
}

type testOwnedDatagramSender struct{ err error }

func (s testOwnedDatagramSender) SendDatagramBufferOwned([]byte, int, int, quic.DatagramPayloadOwner) error {
	return s.err
}

type testPayloadOwner struct{ releases int }

func (o *testPayloadOwner) Release() { o.releases++ }

func TestOwnedDatagramReleaseContract(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantRelease int
	}{
		{name: "transferred", wantRelease: 0},
		{name: "send error", err: errors.New("send failed"), wantRelease: 1},
		{name: "too large", err: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}, wantRelease: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := &testPayloadOwner{}
			err := sendDatagramBufferOwnedOrDrop(testOwnedDatagramSender{err: tc.err}, make([]byte, 16), 0, 1, owner)
			if tc.wantRelease == 0 && err != nil {
				t.Fatal(err)
			}
			if tc.wantRelease > 0 && tc.name == "send error" && err == nil {
				t.Fatal("send error was swallowed")
			}
			if owner.releases != tc.wantRelease {
				t.Fatalf("released %d times, want %d", owner.releases, tc.wantRelease)
			}
		})
	}
}

func TestUDPOwnedDatagramPoolUsesAcquireGenerations(t *testing.T) {
	p := newUDPOwnedDatagramPool()
	b := p.Acquire()
	b.Release()
	b.Release()
	// A new Acquire starts the next valid generation; tests never revive a
	// previously released object by mutating its state directly.
	b = p.Acquire()
	b.Release()
}

func TestProxySharesOwnedDatagramPoolAcrossFlows(t *testing.T) {
	proxy := &Proxy{}
	proxy.mx.Lock()
	first := proxy.sharedOwnedPoolLocked()
	second := proxy.sharedOwnedPoolLocked()
	proxy.mx.Unlock()
	if first != second {
		t.Fatal("proxy created independent owned pools")
	}
}

func TestOversizedDatagramLoggerAggregatesForThirtySeconds(t *testing.T) {
	var logger oversizedDatagramLogger
	if count, ok := logger.Record(time.Unix(100, 0)); !ok || count != 1 {
		t.Fatalf("first record = count %d log %v", count, ok)
	}
	for i := 1; i <= 10; i++ {
		if count, ok := logger.Record(time.Unix(int64(100+i), 0)); ok || count != uint64(i+1) {
			t.Fatalf("burst record %d = count %d log %v", i, count, ok)
		}
	}
	if count, ok := logger.Record(time.Unix(129, 0)); ok || count != 12 {
		t.Fatalf("boundary record = count %d log %v", count, ok)
	}
	if count, ok := logger.Record(time.Unix(130, 0)); !ok || count != 13 {
		t.Fatalf("next-window record = count %d log %v", count, ok)
	}
}

func TestUDPSentinelPreservesOversizedPacketSignal(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver.SetReadDeadline(time.Now().Add(time.Second))

	for _, size := range []int{maxUDPPayloadSize, maxUDPPayloadSize + 1, 4096} {
		if _, err := sender.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, maxUDPPayloadSize+1)
		n, _, err := receiver.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		want := size
		if want > maxUDPPayloadSize+1 {
			want = maxUDPPayloadSize + 1
		}
		if n != want {
			t.Fatalf("size %d: read %d bytes, want %d", size, n, want)
		}
	}
}
