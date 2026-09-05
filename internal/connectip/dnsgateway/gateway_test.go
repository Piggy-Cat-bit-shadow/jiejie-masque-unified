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

func testWriteTCPMessage(t *testing.T, conn net.Conn, message []byte) {
	t.Helper()
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func testReadTCPMessage(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, message); err != nil {
		t.Fatal(err)
	}
	return message
}

func gatewayTCPAddress(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}

func freeGatewayPort(t *testing.T) int {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp4", gatewayTCPAddress(port))
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	if err := udp.Close(); err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	if err := tcp.Close(); err != nil {
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

func TestGatewayTCPPersistentSequentialQueries(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	conn, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, id := range []byte{0x10, 0x20, 0x30} {
		message := testDNSMessage()
		message[0] = id
		testWriteTCPMessage(t, conn, message)
		got := testReadTCPMessage(t, conn)
		if string(got) != string(message) {
			t.Fatalf("response = %x, want %x", got, message)
		}
	}
	if g.Queries() != 3 || g.Errors() != 0 {
		t.Fatalf("queries=%d errors=%d, want 3/0", g.Queries(), g.Errors())
	}
}

func TestGatewayTCPPipelinedQueries(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	conn, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	messages := make([][]byte, 3)
	var pipelined []byte
	for i, id := range []byte{0x41, 0x42, 0x43} {
		messages[i] = testDNSMessage()
		messages[i][0] = id
		frame := make([]byte, 2+len(messages[i]))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(messages[i])))
		copy(frame[2:], messages[i])
		pipelined = append(pipelined, frame...)
	}
	if _, err := conn.Write(pipelined); err != nil {
		t.Fatal(err)
	}
	for _, want := range messages {
		if got := testReadTCPMessage(t, conn); string(got) != string(want) {
			t.Fatalf("response = %x, want %x", got, want)
		}
	}
	if g.Queries() != 3 || g.Errors() != 0 {
		t.Fatalf("queries=%d errors=%d, want 3/0", g.Queries(), g.Errors())
	}
}

func TestGatewayTCPMalformedSecondQuery(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	conn, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	testWriteTCPMessage(t, conn, testDNSMessage())
	_ = testReadTCPMessage(t, conn)
	if _, err := conn.Write([]byte{0, 5, 1, 2, 3, 4, 5}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return g.Errors() == 1 })
	if g.Queries() != 1 {
		t.Fatalf("queries=%d, want 1", g.Queries())
	}
}

func TestGatewayTCPTruncatedSecondQuery(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	conn, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	testWriteTCPMessage(t, conn, testDNSMessage())
	_ = testReadTCPMessage(t, conn)
	if _, err := conn.Write([]byte{0, 100, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else {
		_ = conn.Close()
	}
	waitFor(t, time.Second, func() bool { return g.Errors() == 1 })
	if g.Queries() != 1 {
		t.Fatalf("queries=%d, want 1", g.Queries())
	}
}

func TestGatewayTCPCleanEOFAfterSuccessfulQuery(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	testWriteTCPMessage(t, conn, testDNSMessage())
	_ = testReadTCPMessage(t, conn)
	_ = conn.Close()
	waitFor(t, time.Second, func() bool { return g.Queries() == 1 })
	if g.Errors() != 0 {
		t.Fatalf("errors=%d, want 0", g.Errors())
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayTCPIdleConnectionReleasesConcurrency(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: 50 * time.Millisecond, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	idle, err := net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	time.Sleep(100 * time.Millisecond)
	conn, err := net.DialTimeout("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	testWriteTCPMessage(t, conn, testDNSMessage())
	got := testReadTCPMessage(t, conn)
	if string(got) != string(testDNSMessage()) {
		t.Fatalf("response=%x, want %x", got, testDNSMessage())
	}
	if g.Errors() != 0 {
		t.Fatalf("errors=%d, want 0", g.Errors())
	}
}

func TestGatewayCloseUnblocksIdleTCPClients(t *testing.T) {
	upstream, closeUpstream := startStubDNS(t)
	defer closeUpstream()
	g, err := Start(Config{ListenAddr: netip.MustParseAddr("127.0.0.1"), Port: freeGatewayPort(t), Upstream: upstream, Timeout: time.Minute, Concurrency: 32})
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]net.Conn, 32)
	for i := range clients {
		clients[i], err = net.Dial("tcp4", gatewayTCPAddress(g.tcp.Addr().(*net.TCPAddr).Port))
		if err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %s", elapsed)
	}
	for _, client := range clients {
		_ = client.Close()
	}
}
