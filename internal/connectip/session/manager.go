package session

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
)

type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

// DefaultOutboundQueueSize holds roughly 1.25 MiB at the safe 1280 MTU. It
// remains bounded, but is large enough to absorb pacing / scheduler bursts on
// high-RTT WAN paths before inner TCP packets are dropped and trigger a second
// congestion-control feedback loop.
const DefaultOutboundQueueSize = 1024

type Session struct {
	ID            uint64
	ClientIP      netip.Addr
	ClientIPs     []netip.Addr
	VisibleIP     netip.Addr
	ShadowIP      netip.Addr
	Identity      string
	Conn          PacketConn
	Ctx           context.Context
	Cancel        context.CancelFunc
	Generation    uint64
	Outbound      chan *PacketBuffer
	closeOnce     sync.Once
	outboundMu    sync.Mutex
	packetPool    *PacketPool
	onClose       func(*Session)
	closeReason   atomic.Value
	lastActivity  atomic.Int64
	queueHigh     atomic.Uint64
	queueDropped  atomic.Uint64
	queueEnqueued atomic.Uint64
	queueDequeued atomic.Uint64
}

func (s *Session) OwnsAddress(ip netip.Addr) bool {
	for _, candidate := range s.ClientIPs {
		if candidate == ip {
			return true
		}
	}
	return ip == s.ClientIP
}

// QueueStats is a lock-free snapshot of a session's outbound handoff queue.
// Depth is instantaneous and therefore advisory; the monotonic counters and
// high-water mark are suitable for comparing sustained overload periods.
type QueueStats struct {
	Capacity  uint64
	Depth     uint64
	HighWater uint64
	Enqueued  uint64
	Dequeued  uint64
	Dropped   uint64
}

// AggregateQueueStats is an identity-free snapshot for operational logging.
// It intentionally aggregates active sessions instead of exposing client
// names or tunnel addresses.
type AggregateQueueStats struct {
	Sessions  uint64
	Capacity  uint64
	Depth     uint64
	HighWater uint64
	Enqueued  uint64
	Dequeued  uint64
	Dropped   uint64
}

// AggregateRuntimeStats is an identity-free aggregation of the QUIC runtime
// snapshots exposed by active CONNECT-IP sessions.
type AggregateRuntimeStats struct {
	Connections                  uint64
	CongestionController         string
	CongestionState              string
	CongestionWindows            uint64
	BytesInFlight                uint64
	PacingRate                   uint64
	PacketsLost                  uint64
	BytesLost                    uint64
	SpuriousLosses               uint64
	MaxPacketReordering          uint64
	MaxTimeReordering            time.Duration
	DatagramQueueDepth           uint64
	DatagramQueueHighWater       uint64
	DatagramBlocked              uint64
	DatagramBlockedDuration      time.Duration
	DatagramEnqueue              uint64
	DatagramDequeue              uint64
	DatagramEnqueueBytes         uint64
	DatagramDequeueBytes         uint64
	DatagramNonEmptyDuration     time.Duration
	SendQueueDepth               uint64
	SendQueueHighWater           uint64
	SendQueueHardBlocks          uint64
	SendQueueHardBlockedDuration time.Duration
	SendQueueEnqueue             uint64
	SendQueueDequeue             uint64
	SendQueueEnqueueBytes        uint64
	SendQueueDequeueBytes        uint64
	UDPWrites                    uint64
	UDPWireBytes                 uint64
	GSOBytes                     uint64
	GSOWrites                    uint64
	NonGSOWrites                 uint64
	GSOSegments                  uint64
	SegmentsPerWriteBuckets      [65]uint64
	PacketsPacked                uint64
	PackedBytes                  uint64
	PacingWakeups                uint64
	SendScheduleRequests         uint64
	SendScheduleCoalesced        uint64
	SchedulerTurns               uint64
	TXTurns                      uint64
	TXPackets                    uint64
	TXBytes                      uint64
	RXTurns                      uint64
	RXPackets                    uint64
	TXTurnEndedDueToRXPending    uint64
	YieldPacing                  uint64
	YieldCwnd                    uint64
	YieldSendQueue               uint64
	YieldNoData                  uint64
	YieldPTO                     uint64
	YieldOther                   uint64
	ReceivedPacketQueueDrops     uint64
	QUICPacketsReceived          uint64
	QUICBytesReceived            uint64
	ReceivedDatagramQueueDrops   uint64
	MinRTT                       time.Duration
	LatestRTT                    time.Duration
	SmoothedRTT                  time.Duration
	CurrentPMTU                  uint64
	GSOConnections               uint64
}

func (s *Session) SetCloseReason(reason string) {
	if reason != "" {
		s.closeReason.Store(reason)
	}
}
func (s *Session) CloseReason() string {
	if reason, ok := s.closeReason.Load().(string); ok {
		return reason
	}
	return ""
}

func New(ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	return NewWithContext(context.Background(), ip, identity, conn, onClose)
}
func NewWithContext(parent context.Context, ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	return NewWithContextAndPacketPool(parent, ip, identity, conn, nil, onClose)
}
func NewWithContextAndPacketPool(parent context.Context, ip netip.Addr, identity string, conn PacketConn, packetPool *PacketPool, onClose func(*Session)) *Session {
	return NewWithContextAndPacketPoolAndQueue(parent, ip, identity, conn, packetPool, DefaultOutboundQueueSize, onClose)
}
func NewWithContextAndPacketPoolAndQueue(parent context.Context, ip netip.Addr, identity string, conn PacketConn, packetPool *PacketPool, queueSize int, onClose func(*Session)) *Session {
	return NewWithAddressesAndPacketPoolAndQueue(parent, []netip.Addr{ip}, identity, conn, packetPool, queueSize, onClose)
}
func NewWithAddressesAndPacketPoolAndQueue(parent context.Context, ips []netip.Addr, identity string, conn PacketConn, packetPool *PacketPool, queueSize int, onClose func(*Session)) *Session {
	ctx, cancel := context.WithCancel(parent)
	if queueSize <= 0 {
		queueSize = DefaultOutboundQueueSize
	}
	if len(ips) == 0 {
		panic("session requires at least one client address")
	}
	addresses := append([]netip.Addr(nil), ips...)
	s := &Session{ClientIP: addresses[0], ClientIPs: addresses, VisibleIP: addresses[0], Identity: identity, Conn: conn, Ctx: ctx, Cancel: cancel, Outbound: make(chan *PacketBuffer, queueSize), packetPool: packetPool, onClose: onClose}
	s.Touch(time.Now())
	return s
}

func (s *Session) Touch(now time.Time)     { s.lastActivity.Store(now.UnixNano()) }
func (s *Session) LastActivity() time.Time { return time.Unix(0, s.lastActivity.Load()) }
func (s *Session) TryEnqueue(packet *PacketBuffer) bool {
	s.outboundMu.Lock()
	defer s.outboundMu.Unlock()
	if s.Ctx.Err() != nil {
		s.queueDropped.Add(1)
		s.releasePacket(packet)
		return false
	}
	select {
	case s.Outbound <- packet:
		s.queueEnqueued.Add(1)
		for depth := uint64(len(s.Outbound)); ; {
			old := s.queueHigh.Load()
			if depth <= old || s.queueHigh.CompareAndSwap(old, depth) {
				break
			}
		}
		return true
	default:
		s.queueDropped.Add(1)
		s.releasePacket(packet)
		return false
	}
}
func (s *Session) QueueHighWater() uint64 { return s.queueHigh.Load() }
func (s *Session) QueueDropped() uint64   { return s.queueDropped.Load() }
func (s *Session) RecordDequeued()        { s.queueDequeued.Add(1) }

// RecordDequeuedN records packets removed from Outbound in one bounded drain.
// The queue statistics retain their per-packet meaning while avoiding one
// atomic operation per packet in a writer burst.
func (s *Session) RecordDequeuedN(n int) {
	if n > 0 {
		s.queueDequeued.Add(uint64(n))
	}
}
func (s *Session) QueueStats() QueueStats {
	return QueueStats{
		Capacity: uint64(cap(s.Outbound)), Depth: uint64(len(s.Outbound)),
		HighWater: s.queueHigh.Load(), Enqueued: s.queueEnqueued.Load(),
		Dequeued: s.queueDequeued.Load(), Dropped: s.queueDropped.Load(),
	}
}
func (s *Session) ReleasePacket(packet *PacketBuffer) { s.releasePacket(packet) }
func (s *Session) releasePacket(packet *PacketBuffer) {
	if packet != nil {
		packet.Release()
	} else if s.packetPool != nil {
		s.packetPool.Put(packet)
	}
}
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.outboundMu.Lock()
		s.Cancel()
		for {
			select {
			case packet := <-s.Outbound:
				s.releasePacket(packet)
			default:
				s.outboundMu.Unlock()
				goto drained
			}
		}
	drained:
		_ = s.Conn.Close()
		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

type Manager struct {
	mu                 sync.RWMutex
	sessions           map[netip.Addr]*Session
	sessionsByShadow   map[netip.Addr]*Session
	sessionsByID       map[uint64]*Session
	next               uint64
	shadow             bool
	shadowPool         netip.Prefix
	shadowNext         netip.Addr
	max                int
	excluded           map[netip.Addr]bool
	cooling            map[netip.Addr]time.Time
	cleanupQuarantined map[netip.Addr]struct{}
	reserved           int
	maxPerIdentity     int
	reservedByIdentity map[string]int
	activeByIdentity   map[string]int
	now                func() time.Time
	random             func(uint32) uint32
	reuseDelay         time.Duration
	cleanup            func(netip.Addr) error
	cleanupExecutor    *cleanupExecutor
	cleanupPending     map[netip.Addr]struct{}
	queueOverflowTotal atomic.Uint64
}

const shadowCleanupWorkers = 2

type cleanupJob struct {
	manager *Manager
	ip      netip.Addr
	cleanup func(netip.Addr) error
}

type CleanupStats struct {
	Queued         uint64
	Started        uint64
	Completed      uint64
	Failed         uint64
	Dropped        uint64
	Active         uint64
	MaxActive      uint64
	QueueHighWater uint64
	Quarantined    uint64
}

type cleanupExecutor struct {
	jobs           chan cleanupJob
	stop           chan struct{}
	space          chan struct{}
	closeOnce      sync.Once
	mu             sync.Mutex
	closed         bool
	workers        sync.WaitGroup
	queued         atomic.Uint64
	started        atomic.Uint64
	completed      atomic.Uint64
	failed         atomic.Uint64
	dropped        atomic.Uint64
	active         atomic.Uint64
	maxActive      atomic.Uint64
	queueHighWater atomic.Uint64
}

func newCleanupExecutor(queueSize int) *cleanupExecutor {
	if queueSize < 1 {
		queueSize = 1
	}
	e := &cleanupExecutor{jobs: make(chan cleanupJob, queueSize), stop: make(chan struct{}), space: make(chan struct{}, 1)}
	e.workers.Add(shadowCleanupWorkers)
	for i := 0; i < shadowCleanupWorkers; i++ {
		go e.worker()
	}
	return e
}

func (e *cleanupExecutor) worker() {
	defer e.workers.Done()
	for {
		select {
		case <-e.stop:
			return
		default:
		}
		select {
		case <-e.stop:
			return
		case job := <-e.jobs:
			e.signalSpace()
			select {
			case <-e.stop:
				e.dropped.Add(1)
				e.failed.Add(1)
				job.manager.finishCleanup(job.ip, fmt.Errorf("cleanup executor stopped"))
				return
			default:
			}
			e.started.Add(1)
			active := e.active.Add(1)
			for {
				old := e.maxActive.Load()
				if active <= old || e.maxActive.CompareAndSwap(old, active) {
					break
				}
			}
			err := job.cleanup(job.ip)
			e.active.Add(^uint64(0))
			if err != nil {
				e.failed.Add(1)
			} else {
				e.completed.Add(1)
			}
			job.manager.finishCleanup(job.ip, err)
		}
	}
}

func (e *cleanupExecutor) signalSpace() {
	select {
	case e.space <- struct{}{}:
	default:
	}
}

func (e *cleanupExecutor) enqueue(job cleanupJob) bool {
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return false
		}
		select {
		case e.jobs <- job:
			e.queued.Add(1)
			depth := uint64(len(e.jobs))
			for {
				old := e.queueHighWater.Load()
				if depth <= old || e.queueHighWater.CompareAndSwap(old, depth) {
					break
				}
			}
			e.mu.Unlock()
			return true
		default:
			e.mu.Unlock()
		}
		select {
		case <-e.stop:
			return false
		case <-e.space:
		}
	}
}

func (e *cleanupExecutor) close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.stop)
		e.mu.Unlock()
		e.workers.Wait()
		for {
			select {
			case job := <-e.jobs:
				e.dropped.Add(1)
				e.failed.Add(1)
				job.manager.finishCleanup(job.ip, fmt.Errorf("cleanup executor stopped"))
			default:
				return
			}
		}
	})
}

func (e *cleanupExecutor) stats() CleanupStats {
	return CleanupStats{
		Queued: e.queued.Load(), Started: e.started.Load(), Completed: e.completed.Load(),
		Failed: e.failed.Load(), Dropped: e.dropped.Load(), Active: e.active.Load(),
		MaxActive: e.maxActive.Load(), QueueHighWater: e.queueHighWater.Load(),
	}
}

func (m *Manager) RecordQueueOverflow()       { m.queueOverflowTotal.Add(1) }
func (m *Manager) QueueOverflowTotal() uint64 { return m.queueOverflowTotal.Load() }

func NewManager() *Manager { return &Manager{sessions: map[netip.Addr]*Session{}} }
func NewShadowManager(pool netip.Prefix, max int, excluded []netip.Addr) *Manager {
	return NewShadowManagerWithClock(pool, max, excluded, 0, time.Now, cryptoRandom)
}
func NewShadowManagerWithClock(pool netip.Prefix, max int, excluded []netip.Addr, reuseDelay time.Duration, now func() time.Time, random func(uint32) uint32) *Manager {
	pool = pool.Masked()
	m := NewManager()
	m.shadow = true
	m.shadowPool = pool
	m.shadowNext = netip.Addr{}
	m.max = max
	m.sessionsByShadow = map[netip.Addr]*Session{}
	m.sessionsByID = map[uint64]*Session{}
	m.excluded = map[netip.Addr]bool{}
	m.cooling = map[netip.Addr]time.Time{}
	m.cleanupQuarantined = map[netip.Addr]struct{}{}
	m.cleanupPending = map[netip.Addr]struct{}{}
	m.reuseDelay = reuseDelay
	m.now = now
	m.random = random
	m.reservedByIdentity = map[string]int{}
	m.activeByIdentity = map[string]int{}
	if m.now == nil {
		m.now = time.Now
	}
	if m.random == nil {
		m.random = cryptoRandom
	}
	for _, ip := range excluded {
		m.excluded[ip] = true
	}
	return m
}
func cryptoRandom(n uint32) uint32 {
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[:]) % n
}
func (m *Manager) TryReserve() (func(), error) {
	return m.TryReserveFor("")
}
func (m *Manager) SetMaxSessionsPerClient(max int) {
	m.mu.Lock()
	m.maxPerIdentity = max
	m.mu.Unlock()
}
func (m *Manager) TryReserveFor(identity string) (func(), error) {
	m.mu.Lock()
	if !m.shadow {
		m.mu.Unlock()
		return func() {}, nil
	}
	if len(m.sessionsByID)+m.reserved >= m.max {
		m.mu.Unlock()
		return nil, fmt.Errorf("session capacity exhausted")
	}
	if m.maxPerIdentity > 0 && m.activeByIdentity[identity]+m.reservedByIdentity[identity] >= m.maxPerIdentity {
		m.mu.Unlock()
		return nil, fmt.Errorf("session capacity exhausted for client")
	}
	m.reserved++
	m.reservedByIdentity[identity]++
	released := false
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		if !released {
			released = true
			if m.reserved > 0 {
				m.reserved--
			}
			if m.reservedByIdentity[identity] > 0 {
				m.reservedByIdentity[identity]--
				if m.reservedByIdentity[identity] == 0 {
					delete(m.reservedByIdentity, identity)
				}
			}
		}
		m.mu.Unlock()
	}, nil
}
func (m *Manager) Register(s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.shadow {
		return fmt.Errorf("shadow allocator disabled")
	}
	if len(m.sessionsByID) >= m.max {
		return fmt.Errorf("session capacity exhausted")
	}
	ip, ok := m.allocateLocked()
	if !ok {
		return fmt.Errorf("shadow address pool exhausted")
	}
	m.next++
	s.ID = m.next
	s.Generation = m.next
	s.ShadowIP = ip
	m.sessionsByID[s.ID] = s
	m.activeByIdentity[s.Identity]++
	m.sessionsByShadow[ip] = s
	return nil
}
func (m *Manager) allocateLocked() (netip.Addr, bool) {
	network := ipv4Value(m.shadowPool.Masked().Addr())
	count := uint32(1) << uint(32-m.shadowPool.Bits())
	usable := count - 2
	if usable == 0 {
		return netip.Addr{}, false
	}
	if m.shadowNext.IsValid() {
		// Cursor is already set by the previous allocation.
	} else {
		m.shadowNext = netip.AddrFrom4(ipv4Bytes(network + 1 + m.random(usable)))
	}
	start := ipv4Value(m.shadowNext)
	for i := uint32(0); i < usable; i++ {
		value := network + 1 + ((start - (network + 1) + i) % usable)
		ip := netip.AddrFrom4(ipv4Bytes(value))
		if m.excluded[ip] || m.sessionsByShadow[ip] != nil {
			continue
		}
		if _, pending := m.cleanupPending[ip]; pending {
			continue
		}
		if _, quarantined := m.cleanupQuarantined[ip]; quarantined {
			continue
		}
		if until, ok := m.cooling[ip]; ok {
			if !m.now().Before(until) {
				delete(m.cooling, ip)
			} else {
				continue
			}
		}
		m.shadowNext = netip.AddrFrom4(ipv4Bytes(network + 1 + ((value - (network + 1) + 1) % usable)))
		return ip, true
	}
	return netip.Addr{}, false
}
func (m *Manager) Replace(s *Session) (old *Session) {
	m.mu.Lock()
	m.next++
	s.Generation = m.next
	for _, ip := range s.ClientIPs {
		if candidate := m.sessions[ip]; candidate != nil && candidate != s {
			old = candidate
			break
		}
	}
	for _, ip := range s.ClientIPs {
		m.sessions[ip] = s
	}
	m.mu.Unlock()
	if old != nil && old != s {
		old.Close()
	}
	return old
}
func (m *Manager) RemoveIfCurrent(s *Session) bool {
	m.mu.Lock()
	if m.shadow {
		if m.sessionsByID[s.ID] != s {
			m.mu.Unlock()
			return false
		}
		delete(m.sessionsByID, s.ID)
		delete(m.sessionsByShadow, s.ShadowIP)
		cleanup := m.cleanup
		executor := m.cleanupExecutor
		shadowIP := s.ShadowIP
		if m.activeByIdentity[s.Identity] > 0 {
			m.activeByIdentity[s.Identity]--
			if m.activeByIdentity[s.Identity] == 0 {
				delete(m.activeByIdentity, s.Identity)
			}
		}
		pending := cleanup != nil && executor != nil
		if pending {
			m.cleanupPending[shadowIP] = struct{}{}
		} else if m.reuseDelay > 0 {
			m.cooling[shadowIP] = m.now().Add(m.reuseDelay)
		}
		m.mu.Unlock()
		if pending && !executor.enqueue(cleanupJob{manager: m, ip: shadowIP, cleanup: cleanup}) {
			m.finishCleanup(shadowIP, fmt.Errorf("cleanup executor unavailable"))
		}
		return true
	}
	if m.sessions[s.ClientIP] != s {
		m.mu.Unlock()
		return false
	}
	for _, ip := range s.ClientIPs {
		if m.sessions[ip] == s {
			delete(m.sessions, ip)
		}
	}
	m.mu.Unlock()
	return true
}
func (m *Manager) Lookup(ip netip.Addr) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shadow {
		return m.sessionsByShadow[ip]
	}
	return m.sessions[ip]
}
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shadow {
		return len(m.sessionsByID)
	}
	return len(m.sessions)
}
func (m *Manager) Snapshot() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.sessions)
	if m.shadow {
		n = len(m.sessionsByID)
	}
	out := make([]*Session, 0, n)
	if m.shadow {
		for _, s := range m.sessionsByID {
			out = append(out, s)
		}
	} else {
		for _, s := range m.sessions {
			out = append(out, s)
		}
	}
	return out
}
func (m *Manager) IsShadow() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.shadow }
func (m *Manager) IsShadowAddress(ip netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.shadow && m.shadowPool.Contains(ip)
}

func (m *Manager) SetShadowCleanup(cleanup func(netip.Addr) error) {
	m.mu.Lock()
	m.cleanup = cleanup
	if cleanup != nil && m.shadow && m.cleanupExecutor == nil {
		m.cleanupExecutor = newCleanupExecutor(m.max)
	}
	m.mu.Unlock()
}

func (m *Manager) finishCleanup(ip netip.Addr, cleanupErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, pending := m.cleanupPending[ip]; !pending {
		return
	}
	delete(m.cleanupPending, ip)
	if cleanupErr != nil {
		// A stale conntrack entry can no longer be attributed to its original
		// session after this address is reused. Keep it unavailable until restart.
		m.cleanupQuarantined[ip] = struct{}{}
		return
	}
	if m.reuseDelay > 0 {
		m.cooling[ip] = m.now().Add(m.reuseDelay)
	}
}

func (m *Manager) CleanupStats() CleanupStats {
	m.mu.RLock()
	executor := m.cleanupExecutor
	quarantined := uint64(len(m.cleanupQuarantined))
	m.mu.RUnlock()
	if executor == nil {
		return CleanupStats{Quarantined: quarantined}
	}
	stats := executor.stats()
	stats.Quarantined = quarantined
	return stats
}

func (m *Manager) AggregateQueueStats() AggregateQueueStats {
	var out AggregateQueueStats
	for _, s := range m.Snapshot() {
		stats := s.QueueStats()
		out.Sessions++
		out.Capacity += stats.Capacity
		out.Depth += stats.Depth
		out.HighWater += stats.HighWater
		out.Enqueued += stats.Enqueued
		out.Dequeued += stats.Dequeued
		out.Dropped += stats.Dropped
	}
	return out
}

func (m *Manager) AggregateRuntimeStats() AggregateRuntimeStats {
	var out AggregateRuntimeStats
	for _, s := range m.Snapshot() {
		provider, ok := s.Conn.(interface{ RuntimeStats() quic.RuntimeStats })
		if !ok {
			continue
		}
		stats := provider.RuntimeStats()
		out.Connections++
		if out.CongestionController == "" {
			out.CongestionController = stats.CongestionController
		} else if out.CongestionController != stats.CongestionController {
			out.CongestionController = "mixed"
		}
		if out.CongestionState == "" {
			out.CongestionState = stats.CongestionState
		} else if out.CongestionState != stats.CongestionState {
			out.CongestionState = "mixed"
		}
		out.CongestionWindows += stats.CongestionWindow
		out.BytesInFlight += stats.BytesInFlight
		out.PacingRate += stats.PacingRate
		out.PacketsLost += stats.PacketsLost
		out.BytesLost += stats.BytesLost
		out.SpuriousLosses += stats.SpuriousLosses
		out.MaxPacketReordering = max(out.MaxPacketReordering, stats.MaxPacketReordering)
		out.MaxTimeReordering = max(out.MaxTimeReordering, stats.MaxTimeReordering)
		out.DatagramQueueDepth += stats.DatagramSendQueueDepth
		out.DatagramQueueHighWater += stats.DatagramSendQueueHighWater
		out.DatagramBlocked += stats.DatagramSendBlocked
		out.DatagramBlockedDuration += stats.DatagramSendBlockedDuration
		out.DatagramEnqueue += stats.DatagramSendEnqueue
		out.DatagramDequeue += stats.DatagramSendDequeue
		out.DatagramEnqueueBytes += stats.DatagramSendEnqueueBytes
		out.DatagramDequeueBytes += stats.DatagramSendDequeueBytes
		out.DatagramNonEmptyDuration = max(out.DatagramNonEmptyDuration, stats.DatagramQueueNonEmptyDuration)
		out.SendQueueDepth += stats.SendQueueDepth
		out.SendQueueHighWater += stats.SendQueueHighWater
		out.SendQueueHardBlocks += stats.SendQueueHardBlocks
		out.SendQueueHardBlockedDuration += stats.SendQueueHardBlockedDuration
		out.SendQueueEnqueue += stats.SendQueueEnqueue
		out.SendQueueDequeue += stats.SendQueueDequeue
		out.SendQueueEnqueueBytes += stats.SendQueueEnqueueBytes
		out.SendQueueDequeueBytes += stats.SendQueueDequeueBytes
		out.UDPWrites += stats.UDPWrites
		out.UDPWireBytes += stats.UDPWireBytes
		out.GSOBytes += stats.GSOBytes
		out.GSOWrites += stats.GSOWrites
		out.NonGSOWrites += stats.NonGSOWrites
		out.GSOSegments += stats.GSOSegments
		for i, count := range stats.SegmentsPerWriteBuckets {
			out.SegmentsPerWriteBuckets[i] += count
		}
		out.PacketsPacked += stats.PacketsPacked
		out.PackedBytes += stats.PackedBytes
		out.PacingWakeups += stats.PacingWakeups
		out.SendScheduleRequests += stats.SendScheduleRequests
		out.SendScheduleCoalesced += stats.SendScheduleCoalesced
		out.SchedulerTurns += stats.SchedulerTurns
		out.TXTurns += stats.TXTurns
		out.TXPackets += stats.TXPackets
		out.TXBytes += stats.TXBytes
		out.RXTurns += stats.RXTurns
		out.RXPackets += stats.RXPackets
		out.TXTurnEndedDueToRXPending += stats.TXTurnEndedDueToRXPending
		out.YieldPacing += stats.YieldPacing
		out.YieldCwnd += stats.YieldCwnd
		out.YieldSendQueue += stats.YieldSendQueue
		out.YieldNoData += stats.YieldNoData
		out.YieldPTO += stats.YieldPTO
		out.YieldOther += stats.YieldOther
		out.ReceivedPacketQueueDrops += stats.ReceivedPacketQueueDrops
		out.QUICPacketsReceived += stats.ReceivedPackets
		out.QUICBytesReceived += stats.ReceivedBytes
		out.ReceivedDatagramQueueDrops += stats.ReceivedDatagramQueueDrops
		if stats.MinRTT > 0 && (out.MinRTT == 0 || stats.MinRTT < out.MinRTT) {
			out.MinRTT = stats.MinRTT
		}
		out.LatestRTT = max(out.LatestRTT, stats.LatestRTT)
		out.SmoothedRTT = max(out.SmoothedRTT, stats.SmoothedRTT)
		if stats.CurrentPMTU > 0 && (out.CurrentPMTU == 0 || stats.CurrentPMTU < out.CurrentPMTU) {
			out.CurrentPMTU = stats.CurrentPMTU
		}
		if stats.GSO {
			out.GSOConnections++
		}
	}
	return out
}

func (m *Manager) CloseCleanup() {
	m.mu.RLock()
	executor := m.cleanupExecutor
	m.mu.RUnlock()
	if executor != nil {
		executor.close()
	}
}

func ipv4Value(ip netip.Addr) uint32 {
	a := ip.As4()
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}
func ipv4Bytes(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
