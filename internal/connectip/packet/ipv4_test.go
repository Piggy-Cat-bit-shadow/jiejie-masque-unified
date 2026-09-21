package packet

import (
	"encoding/binary"
	"testing"
)

func TestIPv4DestinationPortAndMalformedPackets(t *testing.T) {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 28)
	p[9] = 17
	binary.BigEndian.PutUint16(p[22:24], 5353)
	if got, ok := Destination(p); !ok || got.String() != "0.0.0.0" {
		t.Fatalf("destination=%v valid=%t", got, ok)
	}
	if !IsTCPOrUDPDestinationPort(p, 5353) {
		t.Fatal("valid UDP port not parsed")
	}
	p[6], p[7] = 0, 1
	if IsTCPOrUDPDestinationPort(p, 5353) {
		t.Fatal("non-first fragment exposed a transport port")
	}
	if IsTCPOrUDPDestinationPort([]byte{0x45}, 5353) {
		t.Fatal("malformed packet accepted")
	}
}
