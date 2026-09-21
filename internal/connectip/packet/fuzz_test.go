package packet

import "testing"

func FuzzIPv4Parser(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b); _, _ = Source(b); _, _ = Destination(b) })
}
