package packet

import (
	"encoding/binary"
	"net/netip"
)

// Info is the bounded, address-family-neutral portion of an inner IP packet
// needed by the dataplane. TransportOffset is zero when no trustworthy TCP or
// UDP header is available (for example a non-first fragment).
type Info struct {
	Version         uint8
	Source          netip.Addr
	Destination     netip.Addr
	Protocol        uint8
	TransportOffset int
	FirstFragment   bool
	Fragmented      bool
}

const maxIPv6ExtensionHeaders = 8
const maxIPv6ExtensionBytes = 256

func Parse(b []byte) (Info, bool) {
	if len(b) == 0 {
		return Info{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	default:
		return Info{}, false
	}
}

func parseIPv4(b []byte) (Info, bool) {
	ihl, total, ok := valid(b)
	if !ok {
		return Info{}, false
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	first := frag&0x1fff == 0
	info := Info{Version: 4, Source: netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), Destination: netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]}), Protocol: b[9], TransportOffset: ihl, FirstFragment: first, Fragmented: frag&0x2000 != 0 || !first}
	if first && (info.Protocol == 6 || info.Protocol == 17) && total >= ihl+4 {
		info.TransportOffset = ihl
	}
	if !first {
		info.TransportOffset = 0
	}
	return info, true
}

func parseIPv6(b []byte) (Info, bool) {
	if len(b) < 40 {
		return Info{}, false
	}
	payload := int(binary.BigEndian.Uint16(b[4:6]))
	// IPv6 jumbograms require Hop-by-Hop Jumbo Payload processing, which this
	// bounded dataplane parser intentionally does not implement. Requiring an
	// exact payload length also prevents silently accepting trailing bytes.
	if payload == 0 || payload != len(b)-40 {
		return Info{}, false
	}
	total := 40 + payload
	if total < 40 || total != len(b) {
		return Info{}, false
	}
	info := Info{Version: 6, Source: netip.AddrFrom16([16]byte(b[8:24])), Destination: netip.AddrFrom16([16]byte(b[24:40])), Protocol: b[6], FirstFragment: true}
	off, next, fragmented, first, ok := walkIPv6Extensions(b[:total], 40, b[6], true)
	if !ok {
		return Info{}, false
	}
	info.Protocol, info.Fragmented, info.FirstFragment = next, fragmented, first
	if first && (next == 6 || next == 17) && off+4 <= total {
		info.TransportOffset = off
	}
	return info, true
}

func walkIPv6Extensions(b []byte, offset int, next uint8, first bool) (int, uint8, bool, bool, bool) {
	fragmented := false
	for i := 0; i < maxIPv6ExtensionHeaders; i++ {
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options.
			if offset+2 > len(b) {
				return 0, 0, false, false, false
			}
			n := b[offset]
			nlen := (int(b[offset+1]) + 1) * 8
			if nlen < 8 || offset+nlen > len(b) || offset+nlen-40 > maxIPv6ExtensionBytes {
				return 0, 0, false, false, false
			}
			next, offset = n, offset+nlen
		case 51: // Authentication Header.
			if offset+2 > len(b) {
				return 0, 0, false, false, false
			}
			n := b[offset]
			nlen := (int(b[offset+1]) + 2) * 4
			if nlen < 8 || offset+nlen > len(b) || offset+nlen-40 > maxIPv6ExtensionBytes {
				return 0, 0, false, false, false
			}
			next, offset = n, offset+nlen
		case 44: // Fragment Header.
			if offset+8 > len(b) {
				return 0, 0, false, false, false
			}
			fragmented = true
			frag := binary.BigEndian.Uint16(b[offset+2 : offset+4])
			first = first && frag>>3 == 0
			next, offset = b[offset], offset+8
			if !first {
				return offset, next, true, false, true
			}
		case 59, 50: // No Next Header / ESP: opaque payload.
			return offset, next, fragmented, first, true
		default:
			return offset, next, fragmented, first, true
		}
	}
	return 0, 0, false, false, false
}
