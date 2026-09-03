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
)

type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

const DefaultOutboundQueueSize = 512

type Session struct {
	ID           uint64
	ClientIP     netip.Addr
	VisibleIP    netip.Addr
	ShadowIP     netip.Addr
	Identity     string
	Conn         PacketConn
	Ctx          context.Context
	Cancel       context.CancelFunc
	Generation   uint64
	Outbound     chan []byte
	closeOnce    sync.Once
	onClose      func(*Session)
	closeReason  atomic.Value
	lastActivity atomic.Int64
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
	ctx, cancel := context.WithCancel(parent)
	s := &Session{ClientIP: ip, VisibleIP: ip, Identity: identity, Conn: conn, Ctx: ctx, Cancel: cancel, Outbound: make(chan []byte, DefaultOutboundQueueSize), onClose: onClose}
	s.Touch(time.Now())
	return s
}

func (s *Session) Touch(now time.Time)     { s.lastActivity.Store(now.UnixNano()) }
func (s *Session) LastActivity() time.Time { return time.Unix(0, s.lastActivity.Load()) }
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.Cancel()
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
	reserved           int
	maxPerIdentity     int
	reservedByIdentity map[string]int
	activeByIdentity   map[string]int
	now                func() time.Time
	random             func(uint32) uint32
	reuseDelay         time.Duration
	cleanup            func(netip.Addr) error
}

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
	old = m.sessions[s.ClientIP]
	m.sessions[s.ClientIP] = s
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
		shadowIP := s.ShadowIP
		if m.activeByIdentity[s.Identity] > 0 {
			m.activeByIdentity[s.Identity]--
			if m.activeByIdentity[s.Identity] == 0 {
				delete(m.activeByIdentity, s.Identity)
			}
		}
		if m.reuseDelay > 0 {
			m.cooling[shadowIP] = m.now().Add(m.reuseDelay)
		}
		m.mu.Unlock()
		if cleanup != nil {
			go func() {
				_ = cleanup(shadowIP)
			}()
		}
		return true
	}
	if m.sessions[s.ClientIP] != s {
		m.mu.Unlock()
		return false
	}
	delete(m.sessions, s.ClientIP)
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
	m.mu.Unlock()
}

func ipv4Value(ip netip.Addr) uint32 {
	a := ip.As4()
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}
func ipv4Bytes(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
