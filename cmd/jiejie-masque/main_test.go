package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/packet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
)

func TestConnectIPRoutesByAddressFamily(t *testing.T) {
	v4 := config.TunnelAddresses{IPv4: netip.MustParsePrefix("10.200.0.2/32")}
	v6 := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::2/128")}
	server := config.TunnelAddresses{IPv6: netip.MustParsePrefix("fd00:200::1/64")}
	assertRoutes := func(name string, got []connectip.IPRoute, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s routes = %#v, want %v", name, got, want)
		}
		for i, route := range got {
			if route.StartIP.String()+"-"+route.EndIP.String() != want[i] {
				t.Fatalf("%s route[%d] = %s-%s, want %s", name, i, route.StartIP, route.EndIP, want[i])
			}
		}
	}
	assertRoutes("IPv4-only", connectIPRoutes(v4, config.TunnelAddresses{}, false), "0.0.0.0-255.255.255.255")
	assertRoutes("IPv6-only local", connectIPRoutes(v6, server, false), "fd00:200::1-fd00:200::1")
	assertRoutes("IPv6-only default", connectIPRoutes(v6, server, true), "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	dual := config.TunnelAddresses{IPv4: v4.IPv4, IPv6: v6.IPv6}
	assertRoutes("dual-stack", connectIPRoutes(dual, server, false), "0.0.0.0-255.255.255.255", "fd00:200::1-fd00:200::1")
}

type scriptedTunReader struct {
	packets [][]byte
	reads   [][]byte
}

func TestTXGRODrainCapabilityGate(t *testing.T) {
	tests := []struct {
		name                   string
		enabled, owned, legacy bool
		want                   bool
	}{
		{name: "owned_only", enabled: true, owned: true, want: true},
		{name: "legacy_only", enabled: true, legacy: true, want: true},
		{name: "no_capability", enabled: true, want: false},
		{name: "disabled", owned: true, legacy: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := txGRODrainEnabled(tt.enabled, tt.owned, tt.legacy); got != tt.want {
				t.Fatalf("txGRODrainEnabled(%t, %t, %t) = %t, want %t", tt.enabled, tt.owned, tt.legacy, got, tt.want)
			}
		})
	}
}

func TestSessionDrainCapabilityGate(t *testing.T) {
	for _, tt := range []struct {
		owned, legacy bool
		want          bool
	}{
		{owned: true, want: true},
		{legacy: true, want: true},
		{want: false},
	} {
		if got := sessionDrainEnabled(tt.owned, tt.legacy); got != tt.want {
			t.Fatalf("sessionDrainEnabled(%t, %t) = %t, want %t", tt.owned, tt.legacy, got, tt.want)
		}
	}
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

func TestSegmentsPerWriteMetrics(t *testing.T) {
	var buckets [65]uint64
	buckets[1] = 4
	buckets[4] = 1
	if got := segmentsPerWriteAverage(buckets); got != 1.6 {
		t.Fatalf("average segments/write = %v, want 1.6", got)
	}
	if got := segmentWritePercentile(buckets, 50); got != 1 {
		t.Fatalf("p50 segments/write = %d, want 1", got)
	}
	if got := segmentWritePercentile(buckets, 90); got != 4 {
		t.Fatalf("p90 segments/write = %d, want 4", got)
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

type writerTestConn struct {
	mu       sync.Mutex
	writes   [][]byte
	owners   []connectip.PacketPayloadOwner
	failAt   int
	icmpAt   int
	blockAt  int
	entered  chan struct{}
	unblock  chan struct{}
	closed   atomic.Int32
	callNext int
}

func (c *writerTestConn) ReadPacket() ([]byte, error) { return nil, context.Canceled }
func (c *writerTestConn) Close() error {
	c.closed.Add(1)
	return nil
}
func (c *writerTestConn) WritePacket(p []byte) ([]byte, error) {
	return c.write(p, nil)
}
func (c *writerTestConn) WritePacketBufferOwned(buf []byte, offset, length int, owner connectip.PacketPayloadOwner) ([]byte, error) {
	return c.write(buf[offset:offset+length], owner)
}
func (c *writerTestConn) write(p []byte, owner connectip.PacketPayloadOwner) ([]byte, error) {
	c.mu.Lock()
	c.callNext++
	call := c.callNext
	c.writes = append(c.writes, append([]byte(nil), p...))
	if owner != nil && call != c.failAt {
		c.owners = append(c.owners, owner)
	}
	block := call == c.blockAt
	entered, unblock := c.entered, c.unblock
	icmpAt, failAt := c.icmpAt, c.failAt
	c.mu.Unlock()
	if block {
		close(entered)
		<-unblock
	}
	if call == failAt {
		return nil, errors.New("writer failure")
	}
	if call == icmpAt {
		return []byte{1, 2, 3, 4}, nil
	}
	return nil, nil
}
func (c *writerTestConn) snapshot() (writes [][]byte, calls int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...), c.callNext
}

type tryWritableTestConn struct {
	writerTestConn
	attempts    atomic.Int32
	writable    chan struct{}
	nilWritable bool
}

type batchWriterTestConn struct {
	writerTestConn
	acceptedPerBatch int
	batchCalls       int
	writable         chan struct{}
	nilWritable      bool
	acceptAfterCall  int
}

func (c *batchWriterTestConn) TryWritePacketBuffersOwnedBatch(packets []connectip.OwnedPacketBuffer) (int, [][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchCalls++
	accepted := min(c.acceptedPerBatch, len(packets))
	if c.acceptAfterCall > 0 && c.batchCalls >= c.acceptAfterCall {
		accepted = len(packets)
	}
	for _, packet := range packets[:accepted] {
		c.owners = append(c.owners, packet.Owner)
	}
	return accepted, make([][]byte, accepted), nil
}

func (c *batchWriterTestConn) DatagramWritable() <-chan struct{} {
	if c.nilWritable {
		return nil
	}
	if c.writable != nil {
		return c.writable
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (c *tryWritableTestConn) TryWritePacketBufferOwned(buf []byte, offset, length int, owner connectip.PacketPayloadOwner) ([]byte, bool, error) {
	if c.attempts.Add(1) == 1 {
		return nil, false, nil
	}
	icmp, err := c.writerTestConn.write(buf[offset:offset+length], owner)
	return icmp, err == nil, err
}

func (c *tryWritableTestConn) DatagramWritable() <-chan struct{} {
	if c.nilWritable {
		return nil
	}
	return c.writable
}
func (c *writerTestConn) releaseTransferred() {
	c.mu.Lock()
	owners := c.owners
	c.owners = nil
	c.mu.Unlock()
	for _, owner := range owners {
		owner.Release()
	}
}

type writerTestTUN struct {
	mu     sync.Mutex
	writes [][]byte
	err    error
}

func (t *writerTestTUN) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), p...))
	err := t.err
	t.mu.Unlock()
	return len(p), err
}

func writerTestPacket(n byte) *session.PacketBuffer {
	buf := make([]byte, session.PacketPoolHeadroom+1)
	buf[session.PacketPoolHeadroom] = n
	return &session.PacketBuffer{Buffer: buf, Data: buf[session.PacketPoolHeadroom:]}
}

func newWriterTestSession(ctx context.Context, conn session.PacketConn) *session.Session {
	return session.NewWithContextAndPacketPoolAndQueue(ctx, netip.MustParseAddr("10.200.0.2"), "writer-test", conn, nil, 256, nil)
}

func waitWriterCalls(t *testing.T, conn *writerTestConn, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, calls := conn.snapshot(); calls >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	_, calls := conn.snapshot()
	t.Fatalf("writer calls = %d, want at least %d", calls, want)
}

func TestSessionWriterSinglePacket(t *testing.T) {
	conn := &writerTestConn{}
	s := newWriterTestSession(context.Background(), conn)
	if !s.TryEnqueue(writerTestPacket(1)) {
		t.Fatal("enqueue failed")
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	waitWriterCalls(t, conn, 1)
	s.Close()
	<-done
	conn.releaseTransferred()
	if got := s.QueueStats(); got.Enqueued != 1 || got.Dequeued != 1 || got.Depth != 0 {
		t.Fatalf("queue stats = %+v", got)
	}
}

func TestSessionWriterOwnedOwnershipTransfers(t *testing.T) {
	conn := &writerTestConn{}
	s := newWriterTestSession(context.Background(), conn)
	if !s.TryEnqueue(writerTestPacket(1)) {
		t.Fatal("enqueue failed")
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	waitWriterCalls(t, conn, 1)
	conn.mu.Lock()
	owners := len(conn.owners)
	conn.mu.Unlock()
	if owners != 1 {
		t.Fatalf("transferred owners = %d, want 1", owners)
	}
	s.Close()
	<-done
	conn.releaseTransferred()
}

func TestSessionWriterWaitsForWritableWithoutBusyLoop(t *testing.T) {
	conn := &tryWritableTestConn{writable: make(chan struct{})}
	s := newWriterTestSession(context.Background(), conn)
	if !s.TryEnqueue(writerTestPacket(1)) {
		t.Fatal("enqueue failed")
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	deadline := time.Now().Add(time.Second)
	for conn.attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := conn.attempts.Load(); got != 1 {
		t.Fatalf("initial send attempts = %d, want 1", got)
	}
	time.Sleep(20 * time.Millisecond)
	if got := conn.attempts.Load(); got != 1 {
		t.Fatalf("writer busy-looped while transport was full: attempts=%d", got)
	}
	close(conn.writable)
	waitWriterCalls(t, &conn.writerTestConn, 1)
	s.Close()
	<-done
	conn.releaseTransferred()
}

func TestSessionBatchWriterTransfersAcceptedPrefixes(t *testing.T) {
	conn := &batchWriterTestConn{acceptedPerBatch: 1}
	s := newWriterTestSession(context.Background(), conn)
	packets := []*session.PacketBuffer{writerTestPacket(1), writerTestPacket(2), writerTestPacket(3)}
	if !newSessionPacketWriter(conn).writeBatch(s, nil, packets) {
		t.Fatal("batch writer failed")
	}
	conn.mu.Lock()
	calls, owners := conn.batchCalls, len(conn.owners)
	conn.mu.Unlock()
	if calls != 3 || owners != 3 {
		t.Fatalf("batch calls=%d owners transferred=%d, want 3 and 3", calls, owners)
	}
	s.Close()
	conn.releaseTransferred()
}

func TestSessionBatchWriterWaitsAfterShortAcceptedPrefix(t *testing.T) {
	writable := make(chan struct{})
	conn := &batchWriterTestConn{acceptedPerBatch: 1, writable: writable}
	s := newWriterTestSession(context.Background(), conn)
	packets := make([]*session.PacketBuffer, 32)
	for i := range packets {
		packets[i] = writerTestPacket(byte(i))
	}
	done := make(chan struct{})
	go func() { newSessionPacketWriter(conn).writeBatch(s, nil, packets); close(done) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn.mu.Lock()
		calls := conn.batchCalls
		conn.mu.Unlock()
		if calls > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	conn.mu.Lock()
	calls, owners := conn.batchCalls, len(conn.owners)
	conn.mu.Unlock()
	if calls != 1 || owners != 1 {
		t.Fatalf("before writable: batch calls=%d transferred owners=%d, want 1 and 1", calls, owners)
	}
	close(writable)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batch writer did not resume after writable notification")
	}
	conn.mu.Lock()
	calls, owners = conn.batchCalls, len(conn.owners)
	conn.mu.Unlock()
	if calls != len(packets) || owners != len(packets) {
		t.Fatalf("after writable: batch calls=%d transferred owners=%d, want %d", calls, owners, len(packets))
	}
	s.Close()
	conn.releaseTransferred()
}

func TestSessionBatchWriterPollsWhenWritableChannelIsNil(t *testing.T) {
	conn := &batchWriterTestConn{nilWritable: true, acceptAfterCall: 2}
	s := newWriterTestSession(context.Background(), conn)
	packet := writerTestPacket(7)
	done := make(chan bool, 1)
	go func() { done <- newSessionPacketWriter(conn).writeBatch(s, nil, []*session.PacketBuffer{packet}) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("batch writer failed while retrying nil writable notifier")
		}
	case <-time.After(time.Second):
		t.Fatal("batch writer remained blocked on nil writable notifier")
	}
	conn.mu.Lock()
	calls, owners := conn.batchCalls, len(conn.owners)
	conn.mu.Unlock()
	if calls != 2 || owners != 1 {
		t.Fatalf("retry calls=%d transferred owners=%d, want 2 and 1", calls, owners)
	}
	s.Close()
	conn.releaseTransferred()
}

func TestSessionBatchWriterDoesNotSpinOnClosedWritableChannel(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	conn := &batchWriterTestConn{writable: closed, acceptAfterCall: 2}
	s := newWriterTestSession(context.Background(), conn)
	packet := writerTestPacket(8)
	done := make(chan bool, 1)
	go func() { done <- newSessionPacketWriter(conn).writeBatch(s, nil, []*session.PacketBuffer{packet}) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer failed to retry a closed generation notification")
	}
	conn.mu.Lock()
	calls := conn.batchCalls
	conn.mu.Unlock()
	if calls != 2 {
		t.Fatalf("batch calls=%d, want one ready retry", calls)
	}
	s.Close()
	conn.releaseTransferred()
}

func TestSessionBatchWriterThrottlesRepeatedClosedNotifications(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	ctx, cancel := context.WithCancel(context.Background())
	conn := &batchWriterTestConn{writable: closed}
	s := newWriterTestSession(ctx, conn)
	done := make(chan bool, 1)
	go func() {
		done <- newSessionPacketWriter(conn).writeBatch(s, nil, []*session.PacketBuffer{writerTestPacket(10)})
	}()
	time.AfterFunc(45*time.Millisecond, cancel)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batch writer ignored cancellation with a closed notifier")
	}
	conn.mu.Lock()
	calls := conn.batchCalls
	conn.mu.Unlock()
	if calls < 2 || calls > 8 {
		t.Fatalf("calls=%d, want bounded retries during cancellation", calls)
	}
	s.Close()
}

func TestSingleWriterPollsNilWritableAndHonorsCancellation(t *testing.T) {
	conn := &tryWritableTestConn{nilWritable: true}
	s := newWriterTestSession(context.Background(), conn)
	pkt := writerTestPacket(9)
	if _, err := newSessionPacketWriter(conn).write(s, pkt); err != nil {
		t.Fatalf("single-packet retry: %v", err)
	}
	if got := conn.attempts.Load(); got != 2 {
		t.Fatalf("try attempts=%d, want 2", got)
	}
	conn.releaseTransferred()
	s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitDatagramWritable(ctx, nil, 0) {
		t.Fatal("nil writable wait ignored canceled context")
	}
}

func TestSessionBatchWriterCancellationUnblocksFullQueue(t *testing.T) {
	conn := &batchWriterTestConn{writable: make(chan struct{})}
	s := newWriterTestSession(context.Background(), conn)
	packets := []*session.PacketBuffer{writerTestPacket(1), writerTestPacket(2)}
	done := make(chan struct{})
	go func() { newSessionPacketWriter(conn).writeBatch(s, nil, packets); close(done) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn.mu.Lock()
		calls := conn.batchCalls
		conn.mu.Unlock()
		if calls > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	conn.mu.Lock()
	calls := conn.batchCalls
	conn.mu.Unlock()
	if calls != 1 {
		t.Fatalf("batch attempts while full = %d, want 1", calls)
	}
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batch writer did not stop after session cancellation")
	}
	conn.mu.Lock()
	owners := len(conn.owners)
	conn.mu.Unlock()
	if owners != 0 {
		t.Fatalf("owners transferred while queue was full: %d", owners)
	}
}

func TestSessionWriterDrainsReadyBurstPreservesOrder(t *testing.T) {
	conn := &writerTestConn{}
	s := newWriterTestSession(context.Background(), conn)
	for i := byte(0); i < 16; i++ {
		if !s.TryEnqueue(writerTestPacket(i)) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	waitWriterCalls(t, conn, 16)
	s.Close()
	<-done
	writes, _ := conn.snapshot()
	conn.releaseTransferred()
	if len(writes) != 16 {
		t.Fatalf("writes = %d, want 16", len(writes))
	}
	for i, p := range writes {
		if len(p) != 1 || p[0] != byte(i) {
			t.Fatalf("write %d = %v, want %d", i, p, i)
		}
	}
}

func TestSessionWriterDoesNotWaitForFuturePacket(t *testing.T) {
	first := writerTestPacket(1)
	queued := make(chan *session.PacketBuffer, 1)
	drained := make(chan []*session.PacketBuffer, 1)
	go func() { drained <- drainSessionWriterReady(first, queued, nil) }()
	select {
	case batch := <-drained:
		if len(batch) != 1 || batch[0] != first {
			t.Fatalf("initial drain = %#v", batch)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ready drain waited for a future packet")
	}

	conn := &writerTestConn{}
	s := newWriterTestSession(context.Background(), conn)
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	if !s.TryEnqueue(writerTestPacket(1)) {
		t.Fatal("first enqueue failed")
	}
	waitWriterCalls(t, conn, 1)
	if !s.TryEnqueue(writerTestPacket(2)) {
		t.Fatal("future enqueue failed")
	}
	waitWriterCalls(t, conn, 2)
	s.Close()
	<-done
	conn.releaseTransferred()
}

func TestSessionWriterDrainBound(t *testing.T) {
	conn := &writerTestConn{blockAt: 1, entered: make(chan struct{}), unblock: make(chan struct{})}
	s := newWriterTestSession(context.Background(), conn)
	for i := 0; i < sessionWriterDrainMax*2; i++ {
		if !s.TryEnqueue(writerTestPacket(byte(i))) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	<-conn.entered
	if got := len(s.Outbound); got != sessionWriterDrainMax {
		t.Fatalf("remaining queue depth = %d, want %d", got, sessionWriterDrainMax)
	}
	close(conn.unblock)
	s.Close()
	<-done
	conn.releaseTransferred()
}

func TestSessionWriterErrorReleasesRemaining(t *testing.T) {
	for _, failAt := range []int{1, 4, 8} {
		t.Run(fmt.Sprintf("at-%d", failAt), func(t *testing.T) {
			conn := &writerTestConn{failAt: failAt}
			s := newWriterTestSession(context.Background(), conn)
			before := time.Unix(1, 0)
			s.Touch(before)
			for i := 0; i < 8; i++ {
				if !s.TryEnqueue(writerTestPacket(byte(i))) {
					t.Fatalf("enqueue %d failed", i)
				}
			}
			done := make(chan struct{})
			go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
			<-done
			_, calls := conn.snapshot()
			conn.releaseTransferred()
			if calls != failAt {
				t.Fatalf("write calls = %d, want %d", calls, failAt)
			}
			if got := s.QueueStats(); got.Depth != 0 || got.Dequeued != 8 {
				t.Fatalf("queue stats = %+v", got)
			}
			if failAt == 1 && !s.LastActivity().Equal(before) {
				t.Fatalf("first-packet failure touched session: %v", s.LastActivity())
			}
			if failAt > 1 && !s.LastActivity().After(before) {
				t.Fatalf("successful packets before failure did not refresh activity: %v", s.LastActivity())
			}
		})
	}
}

func TestSessionWriterICMPResponseAndFailure(t *testing.T) {
	conn := &writerTestConn{icmpAt: 1}
	tun := &writerTestTUN{}
	s := newWriterTestSession(context.Background(), conn)
	if !s.TryEnqueue(writerTestPacket(1)) || !s.TryEnqueue(writerTestPacket(2)) {
		t.Fatal("enqueue failed")
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, tun, 1280); close(done) }()
	waitWriterCalls(t, conn, 2)
	s.Close()
	<-done
	conn.releaseTransferred()
	if len(tun.writes) != 1 {
		t.Fatalf("ICMP writes = %d, want 1", len(tun.writes))
	}

	conn = &writerTestConn{icmpAt: 1}
	tun = &writerTestTUN{err: errors.New("tun failure")}
	s = newWriterTestSession(context.Background(), conn)
	for i := 0; i < 4; i++ {
		if !s.TryEnqueue(writerTestPacket(byte(i))) {
			t.Fatal("enqueue failed")
		}
	}
	done = make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, tun, 1280); close(done) }()
	<-done
	conn.releaseTransferred()
	if got := s.CloseReason(); got != "tun-write-error" {
		t.Fatalf("close reason = %q", got)
	}
	if got := s.QueueStats(); got.Depth != 0 || got.Dequeued != 4 {
		t.Fatalf("queue stats = %+v", got)
	}
}

func TestSessionWriterCloseRaceAndContextCancel(t *testing.T) {
	conn := &writerTestConn{blockAt: 1, entered: make(chan struct{}), unblock: make(chan struct{})}
	s := newWriterTestSession(context.Background(), conn)
	for i := 0; i < sessionWriterDrainMax; i++ {
		if !s.TryEnqueue(writerTestPacket(byte(i))) {
			t.Fatal("enqueue failed")
		}
	}
	done := make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	<-conn.entered
	closeDone := make(chan struct{})
	go func() { s.Close(); close(closeDone) }()
	<-closeDone
	close(conn.unblock)
	<-done
	conn.releaseTransferred()
	if _, calls := conn.snapshot(); calls != 1 {
		t.Fatalf("writes after Close = %d, want 1", calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn = &writerTestConn{}
	s = newWriterTestSession(ctx, conn)
	done = make(chan struct{})
	go func() { sessionWriterWithTUNWriter(s, nil, 1280); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop after context cancellation")
	}
}

func TestReapIdleSessions(t *testing.T) {
	m := session.NewShadowManager(netip.MustParsePrefix("10.200.0.128/29"), 2, nil)
	idle := session.New(netip.MustParseAddr("10.200.0.2"), "idle", testPacketConn{}, func(s *session.Session) { m.RemoveIfCurrent(s) })
	active := session.New(netip.MustParseAddr("10.200.0.2"), "active", testPacketConn{}, func(s *session.Session) { m.RemoveIfCurrent(s) })
	m.Register(idle)
	m.Register(active)
	now := time.Unix(1000, 0)
	idle.Touch(now.Add(-time.Hour))
	active.Touch(now.Add(-time.Minute))
	if got := reapIdle(m, now, 30*time.Minute); got != 1 || m.Len() != 1 || m.Lookup(active.ShadowIPv4) != active {
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

func TestDualStackShadowRewritesIPv4AndPreservesIPv6(t *testing.T) {
	ctx := context.Background()
	pool := session.NewPacketPool(1500)
	mgr := session.NewShadowManager(netip.MustParsePrefix("10.200.0.128/30"), 4, nil)
	v4 := netip.MustParseAddr("10.200.0.2")
	v6 := netip.MustParseAddr("fd00:200::2")
	s := session.NewWithAddressesAndPacketPoolAndQueue(ctx, []netip.Addr{v4, v6}, "dual", testPacketConn{}, pool, 8, func(s *session.Session) { mgr.RemoveIfCurrent(s) })
	if err := mgr.Register(s); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := config.TunnelAddresses{IPv4: netip.MustParsePrefix("10.200.0.1/24"), IPv6: netip.MustParsePrefix("fd00:200::1/64")}

	out4 := make([]byte, 20)
	out4[0], out4[9] = 0x45, 17
	binary.BigEndian.PutUint16(out4[2:4], uint16(len(out4)))
	v4.As4()
	copy(out4[12:16], v4.AsSlice())
	copy(out4[16:20], []byte{1, 1, 1, 1})
	if !prepareSessionPacket(out4, s, mgr, server, false, 0) {
		t.Fatal("IPv4 packet rejected")
	}
	if got := netip.AddrFrom4([4]byte(out4[12:16])); got != s.ShadowIPv4 {
		t.Fatalf("IPv4 source = %s, want shadow %s", got, s.ShadowIPv4)
	}

	out6 := make([]byte, 41)
	out6[0], out6[6] = 0x60, 59
	binary.BigEndian.PutUint16(out6[4:6], 1)
	copy(out6[8:24], v6.AsSlice())
	copy(out6[24:40], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
	before6 := append([]byte(nil), out6...)
	if !prepareSessionPacket(out6, s, mgr, server, false, 0) {
		t.Fatal("IPv6 packet rejected")
	}
	if !bytes.Equal(out6, before6) {
		t.Fatal("IPv6 source/destination was rewritten")
	}

	in4 := make([]byte, 20)
	in4[0], in4[9] = 0x45, 17
	binary.BigEndian.PutUint16(in4[2:4], uint16(len(in4)))
	copy(in4[12:16], []byte{1, 1, 1, 1})
	copy(in4[16:20], s.ShadowIPv4.AsSlice())
	pkt4 := pool.Get(len(in4))
	copy(pkt4.Data, in4)
	if !dispatchTUNPacket(pkt4, mgr, pool) {
		t.Fatal("IPv4 return packet rejected")
	}
	queued4 := <-s.Outbound
	if got := netip.AddrFrom4([4]byte(queued4.Data[16:20])); got != v4 {
		t.Fatalf("IPv4 return destination = %s, want %s", got, v4)
	}
	s.ReleasePacket(queued4)

	in6 := append([]byte(nil), before6...)
	copy(in6[8:24], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
	copy(in6[24:40], v6.AsSlice())
	pkt6 := pool.Get(len(in6))
	copy(pkt6.Data, in6)
	if !dispatchTUNPacket(pkt6, mgr, pool) {
		t.Fatal("IPv6 direct return packet rejected")
	}
	queued6 := <-s.Outbound
	if !bytes.Equal(queued6.Data, in6) {
		t.Fatal("IPv6 return packet was rewritten")
	}
	s.ReleasePacket(queued6)
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
	if queued.Buffer[session.PacketPoolHeadroom-1] != 0 || len(queued.Data) != len(ip) {
		t.Fatalf("packet layout changed: headroom=%#x length=%d", queued.Buffer[0], len(queued.Data))
	}
}

func TestTUNBatchSlotsOnlyReplaceTransferredBuffers(t *testing.T) {
	pool := session.NewPacketPool(1280)
	packets := make([]*session.PacketBuffer, 3)
	bufs := make([][]byte, 3)
	sizes := []int{7, 8, 9}
	fillTUNBatchSlots(packets, bufs, sizes, pool)
	first := append([]*session.PacketBuffer(nil), packets...)
	packets[0] = nil   // simulate handing the first split packet to a session.
	pool.Put(first[0]) // the receiving session eventually releases it.
	fillTUNBatchSlots(packets, bufs, sizes, pool)
	defer releaseTUNBatchSlots(packets, pool)

	if packets[1] != first[1] || packets[2] != first[2] {
		t.Fatal("idle TUN batch slots were needlessly replaced")
	}
	if sizes[0] != 0 || sizes[1] != 0 || sizes[2] != 0 {
		t.Fatalf("batch sizes were not reset: %v", sizes)
	}
	for i := range bufs {
		if bufs[i] == nil || &bufs[i][0] != &packets[i].Buffer[0] {
			t.Fatalf("slot %d does not point at its packet buffer", i)
		}
	}
}

func TestNormalSessionErrorConsumesWrappedTerminalErrors(t *testing.T) {
	active := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		err  error
		ctx  context.Context
		want bool
	}{
		{name: "local close", err: &connectip.CloseError{Remote: false}, ctx: active, want: true},
		{name: "remote close", err: &connectip.CloseError{Remote: true}, ctx: active, want: true},
		{name: "wrapped net closed", err: fmt.Errorf("wrapped close: %w", net.ErrClosed), ctx: active, want: true},
		{name: "wrapped pipe", err: fmt.Errorf("wrapped pipe: %w", io.ErrClosedPipe), ctx: active, want: true},
		{name: "wrapped canceled", err: fmt.Errorf("wrapped cancel: %w", context.Canceled), ctx: active, want: true},
		{name: "arbitrary error", err: errors.New("sentinel"), ctx: active, want: false},
		{name: "active deadline", err: context.DeadlineExceeded, ctx: active, want: false},
		{name: "canceled context", err: errors.New("session stopped"), ctx: canceled, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalSessionError(tt.err, tt.ctx); got != tt.want {
				t.Fatalf("normalSessionError(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

type terminalErrorPacketConn struct {
	readErr  error
	writeErr error
}

func (c terminalErrorPacketConn) ReadPacket() ([]byte, error) { return nil, c.readErr }
func (c terminalErrorPacketConn) WritePacket([]byte) ([]byte, error) {
	return nil, c.writeErr
}
func (terminalErrorPacketConn) Close() error { return nil }

func TestSessionReaderSemanticCloseDoesNotSetReadError(t *testing.T) {
	for _, remote := range []bool{false, true} {
		s := session.New(netip.MustParseAddr("10.200.0.2"), "reader", terminalErrorPacketConn{readErr: &connectip.CloseError{Remote: remote}}, nil)
		sessionReader(s, nil, session.NewManager(), netip.MustParsePrefix("10.200.0.1/32"), false, 0)
		if got := s.CloseReason(); got != "" {
			t.Fatalf("remote=%t close reason = %q, want empty", remote, got)
		}
		s.Close()
	}
}

func TestSessionWriterSemanticCloseDoesNotSetWriteError(t *testing.T) {
	for _, remote := range []bool{false, true} {
		pool := session.NewPacketPool(1280)
		s := session.New(netip.MustParseAddr("10.200.0.2"), "writer", terminalErrorPacketConn{writeErr: &connectip.CloseError{Remote: remote}}, nil)
		s.Outbound <- pool.Get(1)
		done := make(chan struct{})
		go func() {
			sessionWriter(s, nil, 1280)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("sessionWriter did not return on semantic close")
		}
		if got := s.CloseReason(); got != "" {
			t.Fatalf("remote=%t close reason = %q, want empty", remote, got)
		}
		s.Close()
	}
}

func TestSessionReaderWriterArbitraryErrorsKeepReasons(t *testing.T) {
	sr := session.New(netip.MustParseAddr("10.200.0.2"), "reader", terminalErrorPacketConn{readErr: errors.New("boom")}, nil)
	sessionReader(sr, nil, session.NewManager(), netip.MustParsePrefix("10.200.0.1/32"), false, 0)
	if got := sr.CloseReason(); got != "read-error" {
		t.Fatalf("reader close reason = %q, want read-error", got)
	}
	sr.Close()

	pool := session.NewPacketPool(1280)
	sw := session.New(netip.MustParseAddr("10.200.0.2"), "writer", terminalErrorPacketConn{writeErr: errors.New("boom")}, nil)
	sw.Outbound <- pool.Get(1)
	done := make(chan struct{})
	go func() {
		sessionWriter(sw, nil, 1280)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sessionWriter did not return on arbitrary error")
	}
	if got := sw.CloseReason(); got != "write-error" {
		t.Fatalf("writer close reason = %q, want write-error", got)
	}
	sw.Close()
}
