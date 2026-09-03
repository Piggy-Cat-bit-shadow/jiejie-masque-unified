package connectudp

import (
	"bytes"
	"github.com/metacubex/quic-go/quicvarint"
	"testing"
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
