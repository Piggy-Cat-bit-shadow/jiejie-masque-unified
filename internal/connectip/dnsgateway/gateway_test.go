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

func freeGatewayPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

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

func startRecordingUDPStub(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 8)
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			request := append([]byte(nil), b[:n]...)
			select {
			case received <- request:
			default:
			}
			_, _ = udp.WriteToUDP(request, a)
		}
	}()
	return udp.LocalAddr().String(), received, func() { _ = udp.Close() }
}

func TestGatewayRelaysUDPAndTCP(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	port := freeGatewayPort(t)
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: port, Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	msg := testDNSMessage()
	c, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
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
	tcp, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
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
	deadline := time.Now().Add(time.Second)
	for g.Queries() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.Queries() != 2 {
		t.Fatalf("queries = %d", g.Queries())
	}
}

func TestGatewayUDPOversizedRequestIsDroppedWithoutTruncation(t *testing.T) {
	upstream, received, closeUpstream := startRecordingUDPStub(t)
	defer closeUpstream()
	port := freeGatewayPort(t)
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: port, Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	c, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	exact := append(testDNSMessage(), make([]byte, maxUDPRequestSize-12)...)
	if _, err := c.Write(exact); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, maxUDPRequestSize+1)
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(response)
	if err != nil || string(response[:n]) != string(exact) {
		t.Fatalf("exact-limit response length=%d err=%v", n, err)
	}
	select {
	case request := <-received:
		if string(request) != string(exact) {
			t.Fatalf("upstream received %d bytes, want %d", len(request), len(exact))
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive exact-limit request")
	}

	for _, size := range []int{maxUDPRequestSize + 1, 8192} {
		oversized := append(testDNSMessage(), make([]byte, size-12)...)
		if _, err := c.Write(oversized); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for g.Errors() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.Errors() != 2 {
		t.Fatalf("errors after oversized requests = %d, want 2", g.Errors())
	}
	select {
	case request := <-received:
		t.Fatalf("oversized request reached upstream with %d bytes", len(request))
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := c.Write(testDNSMessage()); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(response)
	if err != nil || string(response[:n]) != string(testDNSMessage()) {
		t.Fatalf("post-oversized response length=%d err=%v", n, err)
	}
	if g.Queries() != 2 {
		t.Fatalf("queries = %d, want 2 successful relays", g.Queries())
	}
}
