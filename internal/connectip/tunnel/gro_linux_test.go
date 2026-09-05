//go:build linux

package tunnel

import (
	"encoding/binary"
	"os"
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
