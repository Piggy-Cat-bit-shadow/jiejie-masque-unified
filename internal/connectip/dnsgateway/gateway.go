// Package dnsgateway provides the deliberately narrow DNS service exposed on
// the CONNECT-IP server address. It never listens on an unspecified address.
package dnsgateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	ListenAddr  netip.Addr
	Port        int
	Upstream    string
	Timeout     time.Duration
	Concurrency int
}

const maxUDPRequestSize = 4096

type Gateway struct {
	udp       *net.UDPConn
	tcp       net.Listener
	cfg       Config
	wg        sync.WaitGroup
	mu        sync.Mutex
	closing   bool
	clients   map[net.Conn]struct{}
	closeOnce sync.Once
	closeErr  error

	queries atomic.Uint64
	errors  atomic.Uint64
}

func Start(cfg Config) (*Gateway, error) {
	if !cfg.ListenAddr.Is4() || cfg.Port < 1024 || cfg.Port > 65535 || cfg.Timeout <= 0 || cfg.Concurrency < 1 {
		return nil, fmt.Errorf("invalid DNS gateway configuration")
	}
	if _, _, err := net.SplitHostPort(cfg.Upstream); err != nil {
		return nil, fmt.Errorf("invalid DNS upstream: %w", err)
	}
	listen := net.JoinHostPort(cfg.ListenAddr.String(), fmt.Sprint(cfg.Port))
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: cfg.ListenAddr.AsSlice(), Port: cfg.Port})
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp4", listen)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	g := &Gateway{udp: udp, tcp: tcp, cfg: cfg, clients: make(map[net.Conn]struct{})}
	for range cfg.Concurrency {
		g.wg.Add(1)
		go g.serveUDP()
	}
	g.wg.Add(1)
	go g.serveTCP()
	return g, nil
}

func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closing = true
		err1 := g.udp.Close()
		err2 := g.tcp.Close()
		for conn := range g.clients {
			_ = conn.Close()
		}
		g.mu.Unlock()
		g.wg.Wait()
		if err1 != nil && !errors.Is(err1, net.ErrClosed) {
			g.closeErr = err1
			return
		}
		if err2 != nil && !errors.Is(err2, net.ErrClosed) {
			g.closeErr = err2
		}
	})
	return g.closeErr
}

func (g *Gateway) Queries() uint64 { return g.queries.Load() }
func (g *Gateway) Errors() uint64  { return g.errors.Load() }

func validMessage(b []byte) bool { return len(b) >= 12 }

func (g *Gateway) serveUDP() {
	defer g.wg.Done()
	// Read one byte beyond the accepted request size so an oversized UDP
	// datagram is rejected instead of being forwarded as a truncated DNS packet.
	buf := make([]byte, maxUDPRequestSize+1)
	for {
		n, client, err := g.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n > maxUDPRequestSize {
			g.errors.Add(1)
			continue
		}
		request := append([]byte(nil), buf[:n]...)
		if !validMessage(request) {
			g.errors.Add(1)
			continue
		}
		response, err := g.exchangeUDP(request)
		if err != nil {
			g.errors.Add(1)
			continue
		}
		g.queries.Add(1)
		_, _ = g.udp.WriteToUDP(response, client)
	}
}

func (g *Gateway) exchangeUDP(request []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", g.cfg.Upstream, g.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
		return nil, err
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if !validMessage(buf[:n]) {
		return nil, fmt.Errorf("malformed upstream DNS response")
	}
	return buf[:n], nil
}

func (g *Gateway) serveTCP() {
	defer g.wg.Done()
	sem := make(chan struct{}, g.cfg.Concurrency)
	for {
		conn, err := g.tcp.Accept()
		if err != nil {
			return
		}
		g.mu.Lock()
		if g.closing {
			g.mu.Unlock()
			_ = conn.Close()
			return
		}
		select {
		case sem <- struct{}{}:
			g.clients[conn] = struct{}{}
			g.wg.Add(1)
			g.mu.Unlock()
			go func() { defer g.wg.Done(); defer func() { <-sem }(); g.proxyTCP(conn) }()
		default:
			g.mu.Unlock()
			_ = conn.Close()
			g.errors.Add(1)
		}
	}
}

func (g *Gateway) proxyTCP(client net.Conn) {
	defer client.Close()
	defer g.untrackTCP(client)
	for {
		if err := client.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
			return
		}
		request, readBytes, err := readTCPMessage(client)
		if err != nil {
			if readBytes == 0 && isCleanTCPIdleOrEOF(err) {
				return
			}
			g.errors.Add(1)
			return
		}
		response, err := g.exchangeTCP(request)
		if err != nil {
			g.errors.Add(1)
			return
		}
		if err = client.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
			return
		}
		if err = writeTCPMessage(client, response); err != nil {
			return
		}
		g.queries.Add(1)
	}
}

func (g *Gateway) exchangeTCP(request []byte) ([]byte, error) {
	upstream, err := net.DialTimeout("tcp", g.cfg.Upstream, g.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	defer upstream.Close()
	if err = upstream.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
		return nil, err
	}
	if err = writeTCPMessage(upstream, request); err != nil {
		return nil, err
	}
	response, _, err := readTCPMessage(upstream)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func readTCPMessage(conn net.Conn) ([]byte, int, error) {
	var length [2]byte
	if n, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, n, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 {
		return nil, len(length), fmt.Errorf("invalid DNS TCP message length %d", n)
	}
	message := make([]byte, n)
	if read, err := io.ReadFull(conn, message); err != nil {
		return nil, len(length) + read, err
	}
	return message, len(length) + n, nil
}

func writeTCPMessage(conn net.Conn, message []byte) error {
	if !validMessage(message) || len(message) > 65535 {
		return fmt.Errorf("invalid DNS TCP message length %d", len(message))
	}
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func isCleanTCPIdleOrEOF(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (g *Gateway) untrackTCP(conn net.Conn) {
	g.mu.Lock()
	delete(g.clients, conn)
	g.mu.Unlock()
}

// RunUntilClosed is convenient for callers that own a cancellation context.
func (g *Gateway) RunUntilClosed(ctx context.Context) {
	<-ctx.Done()
	_ = g.Close()
}
