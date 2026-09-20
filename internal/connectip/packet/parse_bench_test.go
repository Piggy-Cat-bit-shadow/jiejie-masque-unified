package packet

import (
	"encoding/binary"
	"testing"
)

func benchmarkPacket(version uint8, protocol uint8, extensions bool, fragment bool) []byte {
	if version == 4 {
		b := make([]byte, 40)
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[8], b[9] = 64, protocol
		b[12], b[16] = 10, 20
		b[19], b[23] = 2, 2
		return b
	}
	b := make([]byte, 60)
	b[0] = 0x60
	b[6] = protocol
	b[8], b[24] = 0xfd, 0x20
	b[23], b[39] = 1, 1
	if extensions {
		b = make([]byte, 68)
		b[0], b[6] = 0x60, 0
		b[40], b[41] = protocol, 0
	}
	if fragment {
		b = make([]byte, 48)
		b[0], b[6] = 0x60, 44
		b[40] = protocol
		binary.BigEndian.PutUint16(b[42:44], 1<<3)
	}
	b[4], b[5] = byte((len(b)-40)>>8), byte(len(b)-40)
	return b
}

func BenchmarkParseHotPaths(b *testing.B) {
	cases := map[string][]byte{
		"ipv4-tcp":           benchmarkPacket(4, 6, false, false),
		"ipv4-udp":           benchmarkPacket(4, 17, false, false),
		"ipv6-tcp":           benchmarkPacket(6, 6, false, false),
		"ipv6-udp":           benchmarkPacket(6, 17, false, false),
		"ipv6-extension":     benchmarkPacket(6, 6, true, false),
		"ipv6-fragment-tail": benchmarkPacket(6, 17, false, true),
	}
	for name, packet := range cases {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for b.Loop() {
				info, ok := Parse(packet)
				if !ok || info.Version == 0 {
					b.Fatal("benchmark packet did not parse")
				}
			}
		})
	}
}
