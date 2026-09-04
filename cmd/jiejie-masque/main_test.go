package main

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/packet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"net/netip"
	"testing"
	"time"
)

type scriptedTunReader struct {
	packets [][]byte
	reads   [][]byte
}

func (r *scriptedTunReader) Read(dst []byte) (int, error) {
	r.reads = append(r.reads, dst)
	if len(r.packets) == 0 {
		return 0, errors.New("closed")
	}
	pkt := r.packets[0]
	r.packets = r.packets[1:]
	copy(dst, pkt)
	return len(pkt), nil
}

func TestProtocolForParse(t *testing.T) {
	for _, protocol := range []string{"connect-ip", "cf-connect-ip"} {
		got, ok := protocolForParse(protocol)
		if !ok || got != "connect-ip" {
			t.Fatalf("%q: got (%q, %t), want (connect-ip, true)", protocol, got, ok)
		}
	}
	if got, ok := protocolForParse("connect-udp"); ok || got != "" {
		t.Fatalf("unexpected protocol acceptance: (%q, %t)", got, ok)
	}
}

func TestRequestTemplateRejectsMalformedAuthority(t *testing.T) {
	for _, host := range []string{"", "user@example.com", "example.com/path", "example.com:bad"} {
		if got, err := requestTemplate(host); err == nil || got != nil {
			t.Fatalf("host %q was accepted", host)
		}
	}
	template, err := requestTemplate("example.com:443")
	if err != nil || template == nil {
		t.Fatalf("valid authority rejected: %v", err)
	}
}

type testPacketConn struct{}

func (testPacketConn) ReadPacket() ([]byte, error)        { return nil, nil }
func (testPacketConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (testPacketConn) Close() error                       { return nil }

func TestReapIdleSessions(t *testing.T) {
	m := session.NewShadowManager(netip.MustParsePrefix("10.200.0.128/29"), 2, nil)
	idle := session.New(netip.MustParseAddr("10.200.0.2"), "idle", testPacketConn{}, func(s *session.Session) { m.RemoveIfCurrent(s) })
	active := session.New(netip.MustParseAddr("10.200.0.2"), "active", testPacketConn{}, func(s *session.Session) { m.RemoveIfCurrent(s) })
	m.Register(idle)
	m.Register(active)
	now := time.Unix(1000, 0)
	idle.Touch(now.Add(-time.Hour))
	active.Touch(now.Add(-time.Minute))
	if got := reapIdle(m, now, 30*time.Minute); got != 1 || m.Len() != 1 || m.Lookup(active.ShadowIP) != active {
		t.Fatalf("reap result=%d len=%d", got, m.Len())
	}
	if idle.CloseReason() != "idle-timeout" {
		t.Fatal("idle reason missing")
	}
	active.Close()
}

func TestIPv4PacketValidation(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[12:16], []byte{10, 200, 0, 2})
	copy(pkt[16:20], []byte{8, 8, 8, 8})
	if src, ok := packet.Source(pkt); !ok || src.String() != "10.200.0.2" {
		t.Fatalf("source = %s, ok = %t", src, ok)
	}
	if dst, ok := packet.Destination(pkt); !ok || dst.String() != "8.8.8.8" {
		t.Fatalf("destination = %s, ok = %t", dst, ok)
	}
	for _, bad := range [][]byte{nil, make([]byte, 19), []byte{0x60, 0, 0, 0}, append([]byte{0x41}, make([]byte, 19)...)} {
		if _, ok := packet.Destination(bad); ok {
			t.Fatal("malformed/non-IPv4 packet accepted")
		}
	}
}

func TestTUNDispatcherReadsDirectlyIntoQueuedPacket(t *testing.T) {
	pool := session.NewPacketPool(1280)
	mgr := session.NewManager()
	s := session.NewWithContextAndPacketPool(context.Background(), netip.MustParseAddr("10.200.0.2"), "client", testPacketConn{}, pool, nil)
	defer s.Close()
	mgr.Replace(s)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[16:20], []byte{10, 200, 0, 2})
	reader := &scriptedTunReader{packets: [][]byte{ip}}
	fatal := make(chan error, 1)
	tunDispatcherReadLoop(reader, mgr, pool, fatal)
	if err := <-fatal; err == nil {
		t.Fatal("expected reader close")
	}
	queued := <-s.Outbound
	defer s.ReleasePacket(queued)
	if len(reader.reads) < 1 || &queued.Data[0] != &reader.reads[0][0] {
		t.Fatal("queued packet was not read directly into its pooled payload")
	}
	if queued.Buffer[0] != 0 || len(queued.Data) != len(ip) {
		t.Fatalf("packet layout changed: headroom=%#x length=%d", queued.Buffer[0], len(queued.Data))
	}
}
