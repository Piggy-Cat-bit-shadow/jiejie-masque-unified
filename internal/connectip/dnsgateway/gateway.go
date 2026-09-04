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

type Gateway struct {
	udp *net.UDPConn
	tcp net.Listener
	cfg Config
	wg  sync.WaitGroup

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
	g := &Gateway{udp: udp, tcp: tcp, cfg: cfg}
	for range cfg.Concurrency {
		g.wg.Add(1)
		go g.serveUDP()
	}
	g.wg.Add(1)
	go g.serveTCP()
	return g, nil
}

func (g *Gateway) Close() error {
	err1 := g.udp.Close()
	err2 := g.tcp.Close()
	g.wg.Wait()
	if err1 != nil && !errors.Is(err1, net.ErrClosed) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, net.ErrClosed) {
		return err2
	}
	return nil
}

func (g *Gateway) Queries() uint64 { return g.queries.Load() }
func (g *Gateway) Errors() uint64  { return g.errors.Load() }

func validMessage(b []byte) bool { return len(b) >= 12 }

func (g *Gateway) serveUDP() {
	defer g.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, client, err := g.udp.ReadFromUDP(buf)
		if err != nil {
			return
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
		select {
		case sem <- struct{}{}:
			g.wg.Add(1)
			go func() { defer g.wg.Done(); defer func() { <-sem }(); g.proxyTCP(conn) }()
		default:
			_ = conn.Close()
			g.errors.Add(1)
		}
	}
}

func (g *Gateway) proxyTCP(client net.Conn) {
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
		return
	}
	var length [2]byte
	if _, err := io.ReadFull(client, length[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n == 0 || n > 65535 {
		g.errors.Add(1)
		return
	}
	request := make([]byte, n)
	if _, err := io.ReadFull(client, request); err != nil || !validMessage(request) {
		g.errors.Add(1)
		return
	}
	upstream, err := net.DialTimeout("tcp", g.cfg.Upstream, g.cfg.Timeout)
	if err != nil {
		g.errors.Add(1)
		return
	}
	defer upstream.Close()
	if err = upstream.SetDeadline(time.Now().Add(g.cfg.Timeout)); err != nil {
		return
	}
	if _, err = upstream.Write(append(length[:], request...)); err != nil {
		g.errors.Add(1)
		return
	}
	if _, err = io.ReadFull(upstream, length[:]); err != nil {
		g.errors.Add(1)
		return
	}
	n = int(binary.BigEndian.Uint16(length[:]))
	if n < 12 {
		g.errors.Add(1)
		return
	}
	response := make([]byte, n)
	if _, err = io.ReadFull(upstream, response); err != nil {
		g.errors.Add(1)
		return
	}
	if _, err = client.Write(append(length[:], response...)); err != nil {
		return
	}
	g.queries.Add(1)
}

// RunUntilClosed is convenient for callers that own a cancellation context.
func (g *Gateway) RunUntilClosed(ctx context.Context) {
	<-ctx.Done()
	_ = g.Close()
}
