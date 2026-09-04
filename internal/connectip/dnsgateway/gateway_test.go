package dnsgateway

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func testDNSMessage() []byte { return []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0} }

func startStubDNS(t *testing.T) (string, func()) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(b[:n], a)
		}
	}()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(h[:]))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				_, _ = c.Write(append(h[:], b...))
			}()
		}
	}()
	return udp.LocalAddr().String(), func() { _ = udp.Close(); _ = tcp.Close() }
}

func TestGatewayRelaysUDPAndTCP(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: 15353, Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	msg := testDNSMessage()
	c, err := net.Dial("udp4", "127.0.0.1:15353")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write(msg); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != string(msg) {
		t.Fatalf("UDP response %x, %v", b[:n], err)
	}
	tcp, err := net.Dial("tcp4", "127.0.0.1:15353")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	frame := append([]byte{0, byte(len(msg))}, msg...)
	if _, err = tcp.Write(frame); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(frame))
	if _, err = io.ReadFull(tcp, got); err != nil || string(got) != string(frame) {
		t.Fatalf("TCP response %x, %v", got, err)
	}
	if g.Queries() != 2 {
		t.Fatalf("queries = %d", g.Queries())
	}
}
