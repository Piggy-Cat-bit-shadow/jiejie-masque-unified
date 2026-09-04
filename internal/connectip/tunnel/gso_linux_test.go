//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func testVirtio(h virtioNetHdr, packet []byte) []byte {
	b := make([]byte, virtioNetHdrLen+len(packet))
	b[0], b[1] = h.flags, h.gsoType
	binary.LittleEndian.PutUint16(b[2:], h.hdrLen)
	binary.LittleEndian.PutUint16(b[4:], h.gsoSize)
	binary.LittleEndian.PutUint16(b[6:], h.csumStart)
	binary.LittleEndian.PutUint16(b[8:], h.csumOffset)
	copy(b[virtioNetHdrLen:], packet)
	return b
}

func testTCPv4Aggregate() []byte {
	p := make([]byte, 20+20+200)
	p[0], p[8], p[9] = 0x45, 64, unix.IPPROTO_TCP
	copy(p[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint32(p[24:], 1000)
	p[32], p[33] = 0x50, 0x18
	for i := range p[40:] {
		p[40+i] = byte(i)
	}
	return p
}

func testTCPv6Aggregate() []byte {
	p := make([]byte, 40+20+200)
	p[0], p[6], p[7] = 0x60, unix.IPPROTO_TCP, 64
	copy(p[8:40], []byte{0x20, 1, 0xdb, 8, 1, 0, 0, 0, 0x20, 1, 0xdb, 8, 2, 0, 0, 0})
	binary.BigEndian.PutUint32(p[44:], 1000)
	p[52], p[53] = 0x50, 0x18
	for i := range p[60:] {
		p[60+i] = byte(i)
	}
	return p
}

func TestHandleVirtioReadGSOTCPv4AndV6(t *testing.T) {
	for _, tt := range []struct {
		name   string
		typ    uint8
		packet []byte
		v6     bool
	}{
		{"v4", unix.VIRTIO_NET_HDR_GSO_TCPV4, testTCPv4Aggregate(), false},
		{"v6", unix.VIRTIO_NET_HDR_GSO_TCPV6, testTCPv6Aggregate(), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bufs := [][]byte{make([]byte, 1282), make([]byte, 1282)}
			sizes := make([]int, 2)
			n, err := handleVirtioRead(testVirtio(virtioNetHdr{gsoType: tt.typ, gsoSize: 100, csumStart: map[bool]uint16{false: 20, true: 40}[tt.v6], csumOffset: 16}, tt.packet), bufs, sizes, 1)
			if err != nil || n != 2 {
				t.Fatalf("split = %d, %v", n, err)
			}
			iphLen, addrAt, addrLen := 20, 12, 4
			if tt.v6 {
				iphLen, addrAt, addrLen = 40, 8, 16
			}
			for i := 0; i < n; i++ {
				p := bufs[i][1 : 1+sizes[i]]
				if len(p) != iphLen+20+100 {
					t.Fatalf("segment %d length = %d", i, len(p))
				}
				if !tt.v6 && ^checksum(p[:iphLen], 0) != 0 {
					t.Fatalf("segment %d IPv4 checksum invalid", i)
				}
				if bufs[i][0] != 0 {
					t.Fatalf("segment %d overwrote CONNECT-IP headroom", i)
				}
				wantSeq := uint32(1000 + i*100)
				if got := binary.BigEndian.Uint32(p[iphLen+4:]); got != wantSeq {
					t.Fatalf("segment %d seq = %d", i, got)
				}
				pseudo := pseudoChecksum(unix.IPPROTO_TCP, p[addrAt:addrAt+addrLen], p[addrAt+addrLen:addrAt+addrLen*2], uint16(len(p)-iphLen))
				if ^checksum(p[iphLen:], pseudo) != 0 {
					t.Fatalf("segment %d TCP checksum invalid", i)
				}
			}
		})
	}
}

func TestHandleVirtioReadNoneAndMalformed(t *testing.T) {
	bufs := [][]byte{make([]byte, 1282)}
	sizes := make([]int, 1)
	p := testTCPv4Aggregate()[:40]
	n, err := handleVirtioRead(testVirtio(virtioNetHdr{}, p), bufs, sizes, 1)
	if err != nil || n != 1 || sizes[0] != len(p) {
		t.Fatalf("GSO_NONE = %d, %d, %v", n, sizes[0], err)
	}
	if _, err = handleVirtioRead([]byte{0}, bufs, sizes, 1); !errors.Is(err, ErrMalformedGSO) {
		t.Fatalf("short header err = %v", err)
	}
	if _, err = handleVirtioRead(testVirtio(virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 100, csumStart: 20, csumOffset: 16}, []byte{0x45}), bufs, sizes, 1); !errors.Is(err, ErrMalformedGSO) {
		t.Fatalf("truncated aggregate err = %v", err)
	}
}

func TestHandleVirtioReadNoneRepairsPartialChecksum(t *testing.T) {
	p := testTCPv4Aggregate()[:40]
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	pseudo := pseudoChecksum(unix.IPPROTO_TCP, p[12:16], p[16:20], 20)
	binary.BigEndian.PutUint16(p[36:], uint16(pseudo))
	bufs := [][]byte{make([]byte, 1282)}
	sizes := make([]int, 1)
	n, err := handleVirtioRead(testVirtio(virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, csumStart: 20, csumOffset: 16}, p), bufs, sizes, 1)
	if err != nil || n != 1 {
		t.Fatalf("GSO_NONE partial checksum = %d, %v", n, err)
	}
	out := bufs[0][1 : 1+sizes[0]]
	if ^checksum(out[20:], pseudo) != 0 {
		t.Fatal("TCP partial checksum was not repaired")
	}
}
