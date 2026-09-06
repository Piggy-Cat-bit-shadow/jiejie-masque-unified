//go:build linux

package tunnel

import (
	"encoding/binary"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func makeTCPv6Segment(seq uint32, payloadLen int, psh bool) []byte {
	p := make([]byte, 60+payloadLen)
	p[0], p[6], p[7] = 0x60, unix.IPPROTO_TCP, 64
	copy(p[8:40], []byte{0x20, 1, 0xdb, 8, 1, 0, 0, 0, 0x20, 1, 0xdb, 8, 2, 0, 0, 0})
	binary.BigEndian.PutUint16(p[40:], 1234)
	binary.BigEndian.PutUint16(p[42:], 443)
	binary.BigEndian.PutUint32(p[44:], seq)
	binary.BigEndian.PutUint32(p[48:], 7)
	p[52], p[53] = 0x50, 0x10
	if psh {
		p[53] |= tcpFlagPSH
	}
	for i := range p[60:] {
		p[60+i] = byte(seq + uint32(i))
	}
	binary.BigEndian.PutUint16(p[56:], ^checksum(p[40:], pseudoChecksum(unix.IPPROTO_TCP, p[8:24], p[24:40], uint16(len(p)-40))))
	binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	return p
}

func makeTCPv4OptionsSegment(seq uint32, payloadLen int, psh bool, options [4]byte) []byte {
	p := make([]byte, 44+payloadLen)
	p[0], p[8], p[9] = 0x46, 64, unix.IPPROTO_TCP
	copy(p[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	copy(p[20:24], options[:])
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:], 1234)
	binary.BigEndian.PutUint16(p[26:], 443)
	binary.BigEndian.PutUint32(p[28:], seq)
	binary.BigEndian.PutUint32(p[32:], 7)
	p[36], p[37] = 0x50, 0x10
	if psh {
		p[37] |= tcpFlagPSH
	}
	for i := range p[44:] {
		p[44+i] = byte(seq + uint32(i))
	}
	pseudo := pseudoChecksum(unix.IPPROTO_TCP, p[12:16], p[16:20], uint16(len(p)-24))
	binary.BigEndian.PutUint16(p[40:], ^checksum(p[24:], pseudo))
	binary.BigEndian.PutUint16(p[10:], ^checksum(p[:24], 0))
	return p
}

func readTXGROPackets(t *testing.T, packets [][]byte, want int) [][]byte {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{f: os.NewFile(uintptr(fds[0]), "gro-psh"), offload: true, txGRO: true}
	defer d.Close()
	defer unix.Close(fds[1])
	if _, err = d.WriteBatch(packets); err != nil {
		t.Fatal(err)
	}
	outputs := make([][]byte, 0, want)
	for len(outputs) < want {
		buf := make([]byte, virtioNetHdrLen+65535)
		n, err := unix.Read(fds[1], buf)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, buf[:n])
	}
	return outputs
}

func assertTXGROAggregate(t *testing.T, packet []byte, ipLen, payloadLen int, psh bool) {
	t.Helper()
	var h virtioNetHdr
	if err := h.decode(packet); err != nil {
		t.Fatal(err)
	}
	if h.gsoSize == 0 || h.hdrLen != uint16(ipLen+20) {
		t.Fatalf("not a TCP GRO aggregate: header=%+v", h)
	}
	p := packet[virtioNetHdrLen:]
	if got := len(p) - ipLen - 20; got != payloadLen {
		t.Fatalf("aggregate payload = %d, want %d", got, payloadLen)
	}
	gotPSH := p[ipLen+13]&tcpFlagPSH != 0
	if gotPSH != psh {
		t.Fatalf("aggregate PSH = %t, want %t", gotPSH, psh)
	}
}

func assertTXGROAggregateDetails(t *testing.T, packet []byte, ipLen, gsoSize, payloadLen int, firstSeq uint32, psh bool, v6 bool) {
	t.Helper()
	var h virtioNetHdr
	if err := h.decode(packet); err != nil {
		t.Fatal(err)
	}
	wantType := uint8(unix.VIRTIO_NET_HDR_GSO_TCPV4)
	if v6 {
		wantType = unix.VIRTIO_NET_HDR_GSO_TCPV6
	}
	if h.flags != unix.VIRTIO_NET_HDR_F_NEEDS_CSUM || h.gsoType != wantType || h.gsoSize != uint16(gsoSize) || h.hdrLen != uint16(ipLen+20) || h.csumStart != uint16(ipLen) || h.csumOffset != 16 {
		t.Fatalf("GSO header = %+v, want type=%d size=%d hdr=%d start=%d offset=16", h, wantType, gsoSize, ipLen+20, ipLen)
	}
	p := packet[virtioNetHdrLen:]
	if len(p) != ipLen+20+payloadLen || binary.BigEndian.Uint32(p[ipLen+4:]) != firstSeq {
		t.Fatalf("aggregate length/sequence = %d/%d, want %d/%d", len(p), binary.BigEndian.Uint32(p[ipLen+4:]), ipLen+20+payloadLen, firstSeq)
	}
	if v6 {
		if binary.BigEndian.Uint16(p[4:]) != uint16(len(p)-40) {
			t.Fatalf("IPv6 payload length = %d, want %d", binary.BigEndian.Uint16(p[4:]), len(p)-40)
		}
	} else if binary.BigEndian.Uint16(p[2:]) != uint16(len(p)) || ^checksum(p[:20], 0) != 0 {
		t.Fatalf("IPv4 aggregate length/checksum invalid: length=%d checksum=%#x", binary.BigEndian.Uint16(p[2:]), checksum(p[:20], 0))
	}
	gotPSH := p[ipLen+13]&tcpFlagPSH != 0
	if gotPSH != psh {
		t.Fatalf("aggregate PSH = %t, want %t", gotPSH, psh)
	}
	addrLen, addrAt := 4, 12
	if v6 {
		addrLen, addrAt = 16, 8
	}
	wantPseudo := uint16(pseudoChecksum(unix.IPPROTO_TCP, p[addrAt:addrAt+addrLen], p[addrAt+addrLen:addrAt+2*addrLen], uint16(len(p)-ipLen)))
	if got := binary.BigEndian.Uint16(p[ipLen+16:]); got != wantPseudo {
		t.Fatalf("TCP checksum seed = %#x, want %#x", got, wantPseudo)
	}
}

func assertPlainTCPPacket(t *testing.T, packet []byte, ipLen, payloadLen int, firstSeq uint32, v6 bool) {
	t.Helper()
	p := packet
	if len(p) != ipLen+20+payloadLen || binary.BigEndian.Uint32(p[ipLen+4:]) != firstSeq {
		t.Fatalf("plain packet length/sequence = %d/%d", len(p), binary.BigEndian.Uint32(p[ipLen+4:]))
	}
	if p[0]>>4 != 4 && p[0]>>4 != 6 {
		t.Fatalf("plain packet version = %#x", p[0]>>4)
	}
	if v6 {
		if binary.BigEndian.Uint16(p[4:]) != uint16(len(p)-40) {
			t.Fatalf("plain IPv6 payload length = %d", binary.BigEndian.Uint16(p[4:]))
		}
	} else if binary.BigEndian.Uint16(p[2:]) != uint16(len(p)) || ^checksum(p[:20], 0) != 0 {
		t.Fatalf("plain IPv4 length/checksum invalid")
	}
}

func TestTXGROSegmentSizeOrderingIPv4(t *testing.T) {
	type testCase struct {
		name       string
		payloads   []int
		psh        []bool
		wantGroups int
		firstLen   int
		firstGSO   int
		firstPSH   bool
	}
	for _, tc := range []testCase{
		{name: "equal", payloads: []int{1200, 1200, 1200}, psh: []bool{false, false, false}, wantGroups: 1, firstLen: 3600, firstGSO: 1200},
		{name: "final-short", payloads: []int{1200, 1200, 600}, psh: []bool{false, false, false}, wantGroups: 1, firstLen: 3000, firstGSO: 1200},
		{name: "two-segment-final-short", payloads: []int{1200, 600}, psh: []bool{false, false}, wantGroups: 1, firstLen: 1800, firstGSO: 1200},
		{name: "middle-short", payloads: []int{1200, 600, 1200}, psh: []bool{false, false, false}, wantGroups: 2, firstLen: 1800, firstGSO: 1200},
		{name: "larger-after-smaller-initial", payloads: []int{600, 1200}, psh: []bool{false, false}, wantGroups: 2, firstLen: 0, firstGSO: 0},
		{name: "larger-later", payloads: []int{1200, 1300}, psh: []bool{false, false}, wantGroups: 2, firstLen: 0, firstGSO: 0},
		{name: "psh-short", payloads: []int{1200, 600}, psh: []bool{false, true}, wantGroups: 1, firstLen: 1800, firstGSO: 1200, firstPSH: true},
		{name: "short-then-psh-full", payloads: []int{1200, 600, 1200}, psh: []bool{false, false, true}, wantGroups: 2, firstLen: 1800, firstGSO: 1200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packets := make([][]byte, len(tc.payloads))
			seq := uint32(1000)
			for i, payloadLen := range tc.payloads {
				packets[i] = makeTCPv4Segment(seq, payloadLen, tc.psh[i])
				seq += uint32(payloadLen)
			}
			outputs := readTXGROPackets(t, packets, tc.wantGroups)
			if tc.firstGSO != 0 {
				assertTXGROAggregateDetails(t, outputs[0], 20, tc.firstGSO, tc.firstLen, 1000, tc.firstPSH, false)
			} else {
				assertPlainTCPPacket(t, outputs[0], 20, tc.payloads[0], 1000, false)
			}
			if tc.wantGroups == 2 {
				if tc.firstGSO != 0 {
					assertPlainTCPPacket(t, outputs[1], 20, tc.payloads[2], 1000+uint32(tc.payloads[0]+tc.payloads[1]), false)
				} else {
					assertPlainTCPPacket(t, outputs[1], 20, tc.payloads[1], 1000+uint32(tc.payloads[0]), false)
				}
			}
		})
	}
}

func TestTXGROSegmentSizeOrderingIPv6(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payloads []int
		groups   int
		firstLen int
	}{
		{name: "equal", payloads: []int{1200, 1200, 1200}, groups: 1, firstLen: 3600},
		{name: "final-short", payloads: []int{1200, 600}, groups: 1, firstLen: 1800},
		{name: "middle-short", payloads: []int{1200, 600, 1200}, groups: 2, firstLen: 1800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packets := make([][]byte, len(tc.payloads))
			seq := uint32(1000)
			for i, payloadLen := range tc.payloads {
				packets[i] = makeTCPv6Segment(seq, payloadLen, false)
				seq += uint32(payloadLen)
			}
			outputs := readTXGROPackets(t, packets, tc.groups)
			assertTXGROAggregateDetails(t, outputs[0], 40, 1200, tc.firstLen, 1000, false, true)
			if tc.groups == 2 {
				assertPlainTCPPacket(t, outputs[1], 40, 1200, 2800, true)
			}
		})
	}
}

func TestTXGROStopsAfterPSHIPv4AndIPv6(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ipLen int
		make  func(uint32, int, bool) []byte
	}{
		{"ipv4", 20, makeTCPv4Segment},
		{"ipv6", 40, makeTCPv6Segment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packets := [][]byte{
				tc.make(1000, 100, false),
				tc.make(1100, 100, true),
				tc.make(1200, 100, false),
			}
			outputs := readTXGROPackets(t, packets, 2)
			if len(outputs) != 2 {
				t.Fatalf("output groups = %d, want 2", len(outputs))
			}
			assertTXGROAggregate(t, outputs[0], tc.ipLen, 200, true)
			if got := len(outputs[1]) - virtioNetHdrLen - tc.ipLen - 20; got != 100 {
				t.Fatalf("post-PSH payload = %d, want 100", got)
			}
			if outputs[1][1] != 0 {
				t.Fatalf("post-PSH packet unexpectedly has GSO type %#x", outputs[1][1])
			}
		})
	}
}

func TestTXGROPSHBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ipLen int
		make  func(uint32, int, bool) []byte
	}{
		{"ipv4", 20, makeTCPv4Segment},
		{"ipv6", 40, makeTCPv6Segment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("finalPSH", func(t *testing.T) {
				outputs := readTXGROPackets(t, [][]byte{tc.make(1000, 100, false), tc.make(1100, 100, false), tc.make(1200, 100, true)}, 1)
				if len(outputs) != 1 {
					t.Fatalf("output groups = %d, want 1", len(outputs))
				}
				assertTXGROAggregate(t, outputs[0], tc.ipLen, 300, true)
			})
			t.Run("initialPSH", func(t *testing.T) {
				outputs := readTXGROPackets(t, [][]byte{tc.make(1000, 100, true), tc.make(1100, 100, false)}, 2)
				if len(outputs) != 2 {
					t.Fatalf("output groups = %d, want 2", len(outputs))
				}
			})
			t.Run("noPSH", func(t *testing.T) {
				outputs := readTXGROPackets(t, [][]byte{tc.make(1000, 100, false), tc.make(1100, 100, false), tc.make(1200, 100, false)}, 1)
				if len(outputs) != 1 {
					t.Fatalf("output groups = %d, want 1", len(outputs))
				}
				assertTXGROAggregate(t, outputs[0], tc.ipLen, 300, false)
			})
			t.Run("multiplePSH", func(t *testing.T) {
				outputs := readTXGROPackets(t, [][]byte{tc.make(1000, 100, false), tc.make(1100, 100, true), tc.make(1200, 100, false), tc.make(1300, 100, true), tc.make(1400, 100, false)}, 3)
				if len(outputs) != 3 {
					t.Fatalf("output groups = %d, want 3", len(outputs))
				}
				assertTXGROAggregate(t, outputs[0], tc.ipLen, 200, true)
				assertTXGROAggregate(t, outputs[1], tc.ipLen, 200, true)
			})
		})
	}
}

func TestTXGRORejectsIPv4Options(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options [4]byte
	}{
		{name: "different-options", options: [4]byte{1, 1, 1, 1}},
		{name: "same-options", options: [4]byte{2, 2, 2, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := makeTCPv4OptionsSegment(1000, 100, false, tc.options)
			second := makeTCPv4OptionsSegment(1100, 100, false, tc.options)
			if _, ok := tcpGROMetaFor(first); ok {
				t.Fatal("IPv4 options packet was accepted as a TX-GRO candidate")
			}
			if _, ok := tcpGROMetaFor(second); ok {
				t.Fatal("IPv4 options packet was accepted as a TX-GRO candidate")
			}
			outputs := readTXGROPackets(t, [][]byte{first, second}, 2)
			if len(outputs) != 2 {
				t.Fatalf("output groups = %d, want 2", len(outputs))
			}
			for i, output := range outputs {
				if output[virtioNetHdrLen] != 0x46 {
					t.Fatalf("output %d was not an independent IPv4-options packet", i)
				}
			}
		})
	}
}

func TestTXGROFragmentFieldSemantics(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field uint16
		want  bool
	}{
		{name: "unfragmented", field: 0, want: true},
		{name: "df", field: 0x4000, want: true},
		{name: "offset-low-byte", field: 1, want: false},
		{name: "offset-high-bits", field: 0x0100, want: false},
		{name: "more-fragments", field: 0x2000, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makeTCPv4Segment(1000, 100, false)
			binary.BigEndian.PutUint16(p[6:8], tc.field)
			binary.BigEndian.PutUint16(p[10:12], 0)
			binary.BigEndian.PutUint16(p[10:12], ^checksum(p[:20], 0))
			_, got := tcpGROMetaFor(p)
			if got != tc.want {
				t.Fatalf("fragment field %#x candidate = %t, want %t", tc.field, got, tc.want)
			}
		})
	}
}

func TestTXGROConcurrentWriteBatch(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{f: os.NewFile(uintptr(fds[0]), "gro-concurrent"), offload: true, txGRO: true}
	defer d.Close()
	defer unix.Close(fds[1])

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, base := range []uint32{1000, 5000} {
		base := base
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.WriteBatch([][]byte{
				makeTCPv4Segment(base, 100, false),
				makeTCPv4Segment(base+100, 100, false),
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	outputs := make([][]byte, 0, 2)
	for len(outputs) < 2 {
		buf := make([]byte, virtioNetHdrLen+65535)
		n, err := unix.Read(fds[1], buf)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, buf[:n])
	}
	seen := map[uint32]bool{}
	for _, output := range outputs {
		var h virtioNetHdr
		if err := h.decode(output); err != nil {
			t.Fatal(err)
		}
		if h.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 || h.gsoSize != 100 || h.hdrLen != 40 {
			t.Fatalf("concurrent aggregate header = %+v", h)
		}
		p := output[virtioNetHdrLen:]
		if len(p) != 20+20+200 || binary.BigEndian.Uint16(p[2:]) != uint16(len(p)) || ^checksum(p[:20], 0) != 0 {
			t.Fatalf("corrupt concurrent IPv4 aggregate: len=%d", len(p))
		}
		seq := binary.BigEndian.Uint32(p[24:])
		if seq != 1000 && seq != 5000 {
			t.Fatalf("unexpected aggregate sequence %d", seq)
		}
		seen[seq] = true
	}
	if len(seen) != 2 {
		t.Fatalf("concurrent batches collapsed or duplicated: seen=%v", seen)
	}
}
