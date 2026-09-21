package session

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// PacketConn is the small CONNECT-IP API used by the server datapath. The
// transport copies or consumes each payload before the call returns.
type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

type Session struct {
	Generation uint64
	ClientIP   netip.Addr
	ClientIPs  []netip.Addr
	ClientIPv4 netip.Addr
	ClientIPv6 netip.Addr
	Identity   string
	Conn       PacketConn
	Ctx        context.Context
	Cancel     context.CancelFunc

	manager   *Manager
	onClose   func(*Session)
	closeOnce sync.Once
	removed   atomic.Bool
}

func (s *Session) OwnsAddress(ip netip.Addr) bool {
	for _, candidate := range s.ClientIPs {
		if candidate == ip {
			return true
		}
	}
	return false
}

func New(ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	return NewWithContext(context.Background(), ip, identity, conn, onClose)
}

func NewWithContext(parent context.Context, ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	return NewWithAddresses(parent, []netip.Addr{ip}, identity, conn, onClose)
}

func NewWithAddresses(parent context.Context, ips []netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	if len(ips) == 0 {
		panic("session requires at least one client address")
	}
	addresses := append([]netip.Addr(nil), ips...)
	ctx, cancel := context.WithCancel(parent)
	s := &Session{ClientIP: addresses[0], ClientIPs: addresses, Identity: identity, Conn: conn, Ctx: ctx, Cancel: cancel, onClose: onClose}
	for _, address := range addresses {
		if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
			cancel()
			panic("session requires unzoned IPv4 and/or IPv6 addresses")
		}
		if address.Is4() {
			if s.ClientIPv4.IsValid() {
				cancel()
				panic("session has multiple IPv4 addresses")
			}
			s.ClientIPv4 = address
		} else if address.Is6() {
			if s.ClientIPv6.IsValid() {
				cancel()
				panic("session has multiple IPv6 addresses")
			}
			s.ClientIPv6 = address
		} else {
			cancel()
			panic("session address is neither IPv4 nor IPv6")
		}
	}
	return s
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.Cancel()
		_ = s.Conn.Close()
		if s.manager != nil {
			s.manager.RemoveIfCurrent(s)
		}
		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

type Manager struct {
	mu             sync.RWMutex
	sessions4      map[netip.Addr]*Session
	sessions6      map[netip.Addr]*Session
	maxSessions    int
	nextGeneration uint64
}

func NewManager(maxSessions ...int) *Manager {
	limit := 0
	if len(maxSessions) > 0 {
		limit = maxSessions[0]
	}
	return &Manager{sessions4: make(map[netip.Addr]*Session), sessions6: make(map[netip.Addr]*Session), maxSessions: limit}
}

// Replace atomically registers every address on s. Existing addresses may be
// taken over only by the same authenticated identity. Old sessions are closed
// after releasing the registry lock so connection shutdown cannot block
// address lookup or a concurrent registration.
func (m *Manager) Replace(s *Session) ([]*Session, error) {
	if s == nil || s.Conn == nil {
		return nil, fmt.Errorf("session and CONNECT-IP connection are required")
	}
	m.mu.Lock()
	oldSet := make(map[*Session]struct{}, 2)
	// An authenticated identity has one active CONNECT-IP session even when
	// its configured address set changes between connections.
	for _, current := range m.snapshotLocked() {
		if current != s && current.Identity == s.Identity {
			oldSet[current] = struct{}{}
		}
	}
	for _, ip := range s.ClientIPs {
		current := m.lookupLocked(ip)
		if current == nil || current == s {
			continue
		}
		if current.Identity != s.Identity {
			m.mu.Unlock()
			return nil, fmt.Errorf("tunnel address %s is already owned by another client", ip)
		}
		oldSet[current] = struct{}{}
	}
	active := m.countLocked()
	if len(oldSet) > 0 {
		active -= len(oldSet)
	}
	if m.maxSessions > 0 && active >= m.maxSessions {
		m.mu.Unlock()
		return nil, fmt.Errorf("session capacity exhausted")
	}
	for old := range oldSet {
		for _, ip := range old.ClientIPs {
			if m.lookupLocked(ip) == old {
				if ip.Is4() {
					delete(m.sessions4, ip)
				} else {
					delete(m.sessions6, ip)
				}
			}
		}
	}
	m.nextGeneration++
	s.Generation = m.nextGeneration
	s.manager = m
	for _, ip := range s.ClientIPs {
		m.mapAddressLocked(ip, s)
	}
	m.mu.Unlock()

	old := make([]*Session, 0, len(oldSet))
	for previous := range oldSet {
		old = append(old, previous)
		previous.Close()
	}
	return old, nil
}

func (m *Manager) lookupLocked(ip netip.Addr) *Session {
	if ip.Is4() {
		return m.sessions4[ip]
	}
	if ip.Is6() {
		return m.sessions6[ip]
	}
	return nil
}

func (m *Manager) mapAddressLocked(ip netip.Addr, s *Session) {
	if ip.Is4() {
		m.sessions4[ip] = s
	} else {
		m.sessions6[ip] = s
	}
}

func (m *Manager) countLocked() int {
	seen := make(map[*Session]struct{}, len(m.sessions4)+len(m.sessions6))
	for _, s := range m.sessions4 {
		seen[s] = struct{}{}
	}
	for _, s := range m.sessions6 {
		seen[s] = struct{}{}
	}
	return len(seen)
}

func (m *Manager) RemoveIfCurrent(s *Session) bool {
	if s == nil || !s.removed.CompareAndSwap(false, true) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := false
	for _, ip := range s.ClientIPs {
		if m.lookupLocked(ip) == s {
			if ip.Is4() {
				delete(m.sessions4, ip)
			} else {
				delete(m.sessions6, ip)
			}
			removed = true
		}
	}
	return removed
}

func (m *Manager) Lookup(ip netip.Addr) *Session {
	m.mu.RLock()
	s := m.lookupLocked(ip)
	m.mu.RUnlock()
	return s
}

func (m *Manager) Len() int {
	m.mu.RLock()
	n := m.countLocked()
	m.mu.RUnlock()
	return n
}

func (m *Manager) Snapshot() []*Session {
	m.mu.RLock()
	seen := make(map[*Session]struct{}, len(m.sessions4)+len(m.sessions6))
	out := make([]*Session, 0, len(m.sessions4)+len(m.sessions6))
	appendSession := func(s *Session) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range m.sessions4 {
		appendSession(s)
	}
	for _, s := range m.sessions6 {
		appendSession(s)
	}
	m.mu.RUnlock()
	return out
}

func (m *Manager) snapshotLocked() []*Session {
	seen := make(map[*Session]struct{}, len(m.sessions4)+len(m.sessions6))
	out := make([]*Session, 0, len(m.sessions4)+len(m.sessions6))
	for _, table := range []map[netip.Addr]*Session{m.sessions4, m.sessions6} {
		for _, s := range table {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}
