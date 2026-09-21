package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseIPv6UDP(t *testing.T) {
	b := make([]byte, 48)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 8)
	b[6] = 17
	b[8] = 0xfd
	b[23] = 1
	b[24] = 0x20
	b[39] = 1
	binary.BigEndian.PutUint16(b[40:42], 53)
	binary.BigEndian.PutUint16(b[42:44], 5353)
	i, ok := Parse(b)
	if !ok || i.Source != netip.MustParseAddr("fd00::1") || i.Destination != netip.MustParseAddr("2000::1") || i.TransportOffset != 40 || !IsTCPOrUDPDestinationPort(b, 5353) {
		t.Fatalf("unexpected parse: %#v, %v", i, ok)
	}
}

func TestParseIPv6NonFirstFragmentHasNoTransport(t *testing.T) {
	b := make([]byte, 56)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 16)
	b[6] = 44
	b[40] = 17
	binary.BigEndian.PutUint16(b[42:44], 1<<3)
	i, ok := Parse(b)
	if !ok || i.TransportOffset != 0 || i.FirstFragment {
		t.Fatalf("fragment parse: %#v, %v", i, ok)
	}
}

func TestParseIPv6RejectsJumbogramAndLengthMismatch(t *testing.T) {
	base := make([]byte, 40)
	base[0], base[6] = 0x60, 59
	if _, ok := Parse(base); ok {
		t.Fatal("unsupported zero-payload jumbogram accepted")
	}
	withPayload := append(append([]byte(nil), base...), 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(withPayload[4:6], 8)
	if _, ok := Parse(withPayload); !ok {
		t.Fatal("well-formed IPv6 payload rejected")
	}
	if _, ok := Parse(append(withPayload, 0)); ok {
		t.Fatal("IPv6 packet with trailing bytes accepted")
	}
	binary.BigEndian.PutUint16(withPayload[4:6], 7)
	if _, ok := Parse(withPayload); ok {
		t.Fatal("IPv6 packet with truncated declared payload accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x60, 0, 0, 0, 0, 8, 17})
	validIPv6UDP := make([]byte, 48)
	validIPv6UDP[0], validIPv6UDP[6] = 0x60, 17
	binary.BigEndian.PutUint16(validIPv6UDP[4:6], 8)
	f.Add(validIPv6UDP)
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b); _ = IsTCPOrUDPDestinationPort(b, 53) })
}
