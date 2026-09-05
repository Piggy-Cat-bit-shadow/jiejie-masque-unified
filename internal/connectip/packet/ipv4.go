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
func RewriteSourceIPv4(b []byte, old, new netip.Addr) bool      { return rewrite(b, old, new, true) }
func RewriteDestinationIPv4(b []byte, old, new netip.Addr) bool { return rewrite(b, old, new, false) }

func icmpCarriesIPv4Quote(typ byte) bool {
	switch typ {
	case 3, 4, 5, 11, 12: // unreachable, source quench, redirect, time exceeded, parameter problem
		return true
	default:
		return false
	}
}

func TranslateICMP(b []byte, visible, shadow netip.Addr, toKernel bool) bool {
	ihl, total, ok := valid(b)
	if !ok || b[9] != 1 || total < ihl+8 {
		return false
	}
	old, new := visible, shadow
	if !toKernel {
		old, new = shadow, visible
	}
	if toKernel {
		if !rewrite(b, old, new, true) {
			return false
		}
	} else if !rewrite(b, old, new, false) {
		return false
	}
	fragment := binary.BigEndian.Uint16(b[6:8])
	if fragment&0x2000 != 0 || fragment&0x1fff != 0 {
		// A fragmented outer packet may not contain a complete ICMP message.
		// Translate only the outer IPv4 address and leave the fragment payload
		// and ICMP checksum untouched.
		checksumIPv4(b[:ihl])
		return true
	}
	if !icmpCarriesIPv4Quote(b[ihl]) {
		// Informational ICMP payload is opaque; it is not a quoted IPv4 packet.
		checksumIPv4(b[:ihl])
		return true
	}
	quote := b[ihl+8 : total]
	if len(quote) >= 20 && quote[0]>>4 == 4 {
		qihl := int(quote[0]&15) * 4
		if qihl >= 20 && qihl <= len(quote) {
			rewriteHeaderWithTransport(quote, visible, shadow, true)
			rewriteHeaderWithTransport(quote, visible, shadow, false)
			if !toKernel {
				rewriteHeaderWithTransport(quote, shadow, visible, true)
				rewriteHeaderWithTransport(quote, shadow, visible, false)
			}
		}
	}
	checksumIPv4(b[:ihl])
	binary.BigEndian.PutUint16(b[ihl+2:ihl+4], 0)
	binary.BigEndian.PutUint16(b[ihl+2:ihl+4], checksum(b[ihl:total]))
	return true
}
func Source(b []byte) (netip.Addr, bool) {
	if _, _, ok := valid(b); !ok {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}
func Destination(b []byte) (netip.Addr, bool) {
	if _, _, ok := valid(b); !ok {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]}), true
}

// IsTCPOrUDPDestinationPort is intentionally strict. A non-initial fragment
// has no trustworthy transport header and must not be used to bypass a local
// service policy.
func IsTCPOrUDPDestinationPort(b []byte, port uint16) bool {
	ihl, total, ok := valid(b)
	if !ok || (b[9] != 6 && b[9] != 17) || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 || total < ihl+4 {
		return false
	}
	return binary.BigEndian.Uint16(b[ihl+2:ihl+4]) == port
}
func rewrite(b []byte, old, new netip.Addr, src bool) bool {
	ihl, total, ok := valid(b)
	if !ok || !old.Is4() || !new.Is4() {
		return false
	}
	var oi, ni int
	if src {
		oi, ni = 12, 12
	} else {
		oi, ni = 16, 16
	}
	o := old.As4()
	n := new.As4()
	if !equal4(b[oi:oi+4], o[:]) {
		return false
	}
	old1, old2 := binary.BigEndian.Uint16(b[oi:oi+2]), binary.BigEndian.Uint16(b[oi+2:oi+4])
	new1, new2 := binary.BigEndian.Uint16(n[:2]), binary.BigEndian.Uint16(n[2:])
	update16(b[10:12], binary.BigEndian.Uint16(b[10:12]), old1, new1)
	update16(b[10:12], binary.BigEndian.Uint16(b[10:12]), old2, new2)
	copy(b[ni:ni+4], n[:])
	proto := b[9]
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x1fff == 0 && proto == 6 && total >= ihl+18 {
		updateTransport(b, ihl, old1, old2, new1, new2)
	}
	if frag&0x1fff == 0 && proto == 17 && total >= ihl+8 && binary.BigEndian.Uint16(b[ihl+6:ihl+8]) != 0 {
		updateTransport(b, ihl, old1, old2, new1, new2)
	}
	return true
}
func rewriteHeader(b []byte, old, new netip.Addr, src bool) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	off := 16
	if src {
		off = 12
	}
	o := old.As4()
	n := new.As4()
	if !equal4(b[off:off+4], o[:]) {
		return false
	}
	copy(b[off:off+4], n[:])
	checksumIPv4(b[:int(b[0]&15)*4])
	return true
}

func rewriteHeaderWithTransport(b []byte, old, new netip.Addr, src bool) bool {
	if !rewriteHeader(b, old, new, src) {
		return false
	}
	if len(b) < 20 {
		return true
	}
	ihl := int(b[0]&15) * 4
	if ihl > len(b) || b[9] == 1 || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return true
	}
	o, n := old.As4(), new.As4()
	old1, old2 := binary.BigEndian.Uint16(o[:2]), binary.BigEndian.Uint16(o[2:])
	new1, new2 := binary.BigEndian.Uint16(n[:2]), binary.BigEndian.Uint16(n[2:])
	if b[9] == 6 && ihl+18 <= len(b) {
		updateTransport(b, ihl, old1, old2, new1, new2)
	}
	if b[9] == 17 && ihl+8 <= len(b) && binary.BigEndian.Uint16(b[ihl+6:ihl+8]) != 0 {
		updateTransport(b, ihl, old1, old2, new1, new2)
	}
	return true
}
func checksumIPv4(h []byte) {
	binary.BigEndian.PutUint16(h[10:12], 0)
	binary.BigEndian.PutUint16(h[10:12], checksum(h))
}
func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func equal4(a, b []byte) bool {
	return len(a) == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}
func update16(field []byte, cur, old, new uint16) {
	sum := uint32(^cur)
	sum += uint32(^old)
	sum += uint32(new)
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	binary.BigEndian.PutUint16(field, ^uint16(sum))
}
func updateTransport(b []byte, ihl int, old1, old2, new1, new2 uint16) {
	field := ihl + 16
	if b[9] == 17 {
		field = ihl + 6
	}
	limit := len(b)
	if declared := int(binary.BigEndian.Uint16(b[2:4])); declared < limit {
		limit = declared
	}
	if field+2 > limit {
		return
	}
	update16(b[field:field+2], binary.BigEndian.Uint16(b[field:field+2]), old1, new1)
	update16(b[field:field+2], binary.BigEndian.Uint16(b[field:field+2]), old2, new2)
}
