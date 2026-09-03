package connectudp

import (
	"bytes"
	"github.com/metacubex/quic-go/quicvarint"
	"testing"

	"github.com/metacubex/quic-go"
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
