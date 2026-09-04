package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func tcpPacket(src, dst netip.Addr) []byte {
	b := make([]byte, 24+24+5)
	b[0] = 0x46
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = 6
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	for i := 20; i < 24; i++ {
		b[i] = byte(i)
	}
	b[24+12] = 0x50
	copy(b[48:], []byte{1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(b[24+16:24+18], transportChecksum(b, 24, 6, src, dst))
	checksumIPv4(b[:20])
	return b
}

func transportChecksum(pkt []byte, off, proto int, src, dst netip.Addr) uint16 {
	segment := pkt[off:]
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.AsSlice())
	copy(pseudo[4:8], dst.AsSlice())
	pseudo[9] = byte(proto)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return checksum(pseudo)
}

func assertTCPChecksum(t *testing.T, b []byte) {
	t.Helper()
	s, _ := Source(b)
	d, _ := Destination(b)
	if got := transportChecksum(b, int(b[0]&15)*4, 6, s, d); got != 0 {
		t.Fatalf("TCP checksum = %#x", got)
	}
}

func assertIPv4Checksum(t *testing.T, b []byte) {
	t.Helper()
	ihl := int(b[0]&15) * 4
	if checksum(b[:ihl]) != 0 {
		t.Fatalf("IPv4 checksum invalid")
	}
}
func TestRewriteTCPAndUDPAddresses(t *testing.T) {
	old := netip.MustParseAddr("10.200.0.2")
	newIP := netip.MustParseAddr("10.200.0.128")
	dst := netip.MustParseAddr("8.8.8.8")
	b := tcpPacket(old, dst)
	if !RewriteSourceIPv4(b, old, newIP) {
		t.Fatal("tcp rewrite failed")
	}
	if s, _ := Source(b); s != newIP {
		t.Fatal("tcp source not rewritten")
	}
	if b[10] == 0 && b[11] == 0 {
		t.Fatal("header checksum not updated")
	}
	assertTCPChecksum(t, b)
	if !RewriteDestinationIPv4(b, dst, old) {
		t.Fatal("tcp destination rewrite failed")
	}
	assertTCPChecksum(t, b)
	u := make([]byte, 28)
	u[0] = 0x45
	binary.BigEndian.PutUint16(u[2:4], 28)
	u[9] = 17
	copy(u[12:16], old.AsSlice())
	copy(u[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(u[26:28], 0)
	if !RewriteSourceIPv4(u, old, newIP) || binary.BigEndian.Uint16(u[26:28]) != 0 {
		t.Fatal("UDP zero checksum changed")
	}
}

func TestUDPChecksumAndTrailingBytes(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	b := make([]byte, 20+8+5+16)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 33)
	b[9] = 17
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	b[20] = 0x12
	b[21] = 0x34
	binary.BigEndian.PutUint16(b[24:26], 13)
	b[28], b[29], b[30], b[31], b[32] = 9, 8, 7, 6, 5
	binary.BigEndian.PutUint16(b[26:28], transportChecksum(b[:33], 20, 17, src, dst))
	if !RewriteSourceIPv4(b, src, netip.MustParseAddr("10.200.0.128")) {
		t.Fatal("UDP rewrite failed")
	}
	newSrc, _ := Source(b)
	if transportChecksum(b[:33], 20, 17, newSrc, dst) != 0 {
		t.Fatal("UDP checksum invalid after source rewrite")
	}
	if !RewriteDestinationIPv4(b, dst, src) {
		t.Fatal("UDP destination rewrite failed")
	}
	newDst, _ := Destination(b)
	if transportChecksum(b[:33], 20, 17, newSrc, newDst) != 0 {
		t.Fatal("UDP checksum invalid after destination rewrite")
	}
}
func TestFragmentAndICMPTranslation(t *testing.T) {
	old := netip.MustParseAddr("10.200.0.2")
	shadow := netip.MustParseAddr("10.200.0.128")
	dst := netip.MustParseAddr("8.8.8.8")
	q := tcpPacket(shadow, dst)
	q[6] = 0x20
	q[7] = 0
	outer := make([]byte, 20+8+len(q))
	outer[0] = 0x45
	binary.BigEndian.PutUint16(outer[2:4], uint16(len(outer)))
	outer[9] = 1
	copy(outer[16:20], shadow.AsSlice())
	outer[20] = 3
	outer[21] = 4
	copy(outer[28:], q)
	checksumIPv4(outer[:20])
	if !TranslateICMP(outer, old, shadow, false) {
		t.Fatal("ICMP translation failed")
	}
	if d, _ := Destination(outer); d != old {
		t.Fatal("outer destination not translated")
	}
	if s, _ := Source(outer[28:]); s != old {
		t.Fatal("quoted source not translated")
	}
	assertIPv4Checksum(t, outer)
	if checksum(outer[20:]) != 0 {
		t.Fatal("ICMP checksum invalid")
	}
	assertTCPChecksum(t, outer[28:])
}

func TestICMPMessageTypes(t *testing.T) {
	old := netip.MustParseAddr("10.200.0.2")
	shadow := netip.MustParseAddr("10.200.0.128")
	for _, typ := range []byte{0, 3, 11} { // echo reply, unreachable, time exceeded
		b := make([]byte, 28)
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[9] = 1
		copy(b[12:16], netip.MustParseAddr("8.8.8.8").AsSlice())
		copy(b[16:20], shadow.AsSlice())
		b[20], b[21] = typ, 0
		if !TranslateICMP(b, old, shadow, false) {
			t.Fatalf("type %d translation failed", typ)
		}
		if d, _ := Destination(b); d != old || checksum(b[:20]) != 0 || checksum(b[20:]) != 0 {
			t.Fatalf("type %d checksum/address invalid", typ)
		}
	}
}

func TestIsTCPOrUDPDestinationPortRejectsFragmentsAndMalformed(t *testing.T) {
	b := tcpPacket(netip.MustParseAddr("10.200.0.2"), netip.MustParseAddr("10.200.0.1"))
	binary.BigEndian.PutUint16(b[26:28], 5353)
	if !IsTCPOrUDPDestinationPort(b, 5353) {
		t.Fatal("TCP destination port was not recognized")
	}
	b[6], b[7] = 0, 1 // non-initial fragment: no trusted L4 header
	if IsTCPOrUDPDestinationPort(b, 5353) {
		t.Fatal("fragment bypassed L4 policy")
	}
	if IsTCPOrUDPDestinationPort([]byte{0x45}, 5353) {
		t.Fatal("malformed packet was accepted")
	}
}
