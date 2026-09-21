package packet

import (
	"encoding/binary"
	"net/netip"
)

func valid(b []byte) (int, int, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return 0, 0, false
	}
	ihl := int(b[0]&15) * 4
	if ihl < 20 || ihl > len(b) {
		return 0, 0, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		return 0, 0, false
	}
	return ihl, total, true
}

func Source(b []byte) (netip.Addr, bool)      { i, ok := Parse(b); return i.Source, ok }
func Destination(b []byte) (netip.Addr, bool) { i, ok := Parse(b); return i.Destination, ok }

// IsTCPOrUDPDestinationPort only matches a complete, first-fragment transport header.
func IsTCPOrUDPDestinationPort(b []byte, port uint16) bool {
	i, ok := Parse(b)
	if !ok || (i.Protocol != 6 && i.Protocol != 17) || i.TransportOffset == 0 || len(b) < i.TransportOffset+4 {
		return false
	}
	return binary.BigEndian.Uint16(b[i.TransportOffset+2:i.TransportOffset+4]) == port
}
