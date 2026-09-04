package connectudp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	metatls "github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func resetKey(path string) (*quic.StatelessResetKey, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		if len(b) != len(quic.StatelessResetKey{}) {
			return nil, fmt.Errorf("invalid reset key length")
		}
		var k quic.StatelessResetKey
		copy(k[:], b)
		return &k, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	var k quic.StatelessResetKey
	if _, e = rand.Read(k[:]); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		if errors.Is(e, os.ErrExist) {
			for i := 0; i < 100; i++ {
				if b, readErr := os.ReadFile(path); readErr == nil && len(b) == len(quic.StatelessResetKey{}) {
					var existing quic.StatelessResetKey
					copy(existing[:], b)
					return &existing, nil
				}
				time.Sleep(time.Millisecond)
			}
			return nil, fmt.Errorf("reset key remained incomplete after concurrent creation")
		}
		return nil, e
	}
	defer f.Close()
	n, e := f.Write(k[:])
	cleanup := func() { _ = f.Close(); _ = os.Remove(path) }
	if e != nil || n != len(k) {
		cleanup()
		if e == nil {
			e = io.ErrShortWrite
		}
		return nil, e
	}
	if e = f.Sync(); e != nil {
		cleanup()
		return nil, e
	}
	if e = f.Close(); e != nil {
		_ = os.Remove(path)
		return nil, e
	}
	confirmed, e := os.ReadFile(path)
	if e != nil || len(confirmed) != len(k) || !bytes.Equal(confirmed, k[:]) {
		_ = os.Remove(path)
		return nil, fmt.Errorf("confirm reset key: %w", e)
	}
	return &k, nil
}
func Serve(c Config) error {
	return ServeContext(context.Background(), c)
}
func ServeContext(ctx context.Context, c Config) error {
	return serveContext(ctx, c, nil)
}

func serveContext(ctx context.Context, c Config, ready chan<- string) error {
	return serveContextWithReaper(ctx, c, ready, time.Minute)
}

func serveContextWithReaper(ctx context.Context, c Config, ready chan<- string, reaperInterval time.Duration) error {
	return serveContextWithState(ctx, c, ready, reaperInterval, nil)
}

type serverState struct {
	flows     *FlowTracker
	relay     *TCPRelay
	admission *Admission
}

func serveContextWithState(ctx context.Context, c Config, ready chan<- string, reaperInterval time.Duration, state *serverState) error {
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	creds, err := c.ResolveCredentials()
	if err != nil {
		return err
	}
	cert, e := metatls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if e != nil {
		return e
	}
	rk, e := resetKey(c.QUIC.StatelessResetKeyFile)
	if e != nil {
		return e
	}
	listenAddr, e := net.ResolveUDPAddr("udp", c.Listen)
	if e != nil {
		return fmt.Errorf("invalid listen address: %w", e)
	}
	t, e := net.ListenUDP("udp", listenAddr)
	if e != nil {
		return e
	}
	defer t.Close()
	qt := &quic.Transport{Conn: t, StatelessResetKey: rk}
	defer qt.Close()
	qc := &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 10 * time.Second, KeepAlivePeriod: c.KeepAlive(), MaxIdleTimeout: c.IdleTimeout(), MaxIncomingStreams: 64}
	ql, e := qt.Listen(http3.ConfigureTLSConfig(&metatls.Config{Certificates: []metatls.Certificate{cert}}), qc)
	if e != nil {
		return e
	}
	defer ql.Close()
	u, e := uritemplate.New("https://" + c.PublicAuthority + "/.well-known/masque/udp/{target_host}/{target_port}/")
	if e != nil {
		return e
	}
	p := &Proxy{Policy: c.TargetPolicy}
	tcpRelay := &TCPRelay{Policy: c.TargetPolicy}
	admission := NewAdmission(maxOr(c.Limits.MaxActiveFlows, 256), maxOr(c.Limits.MaxActiveFlowsPerUser, 64))
	flows := NewFlowTracker()
	if state != nil {
		state.flows, state.relay, state.admission = flows, tcpRelay, admission
	}
	go flows.Run(runCtx.Done(), c.FlowIdleTimeout(), reaperInterval)
	h := mh.HandlerFunc(func(w mh.ResponseWriter, r *mh.Request) {
		if r.Proto == "connect-udp" {
			q, e := ParseProxyRequest(r, u)
			if e != nil {
				var pe *ProxyRequestParseError
				if errors.As(e, &pe) {
					w.WriteHeader(pe.HTTPStatus)
				} else {
					w.WriteHeader(400)
				}
				return
			}
			release, err := admission.Acquire(Identity(r))
			if err != nil {
				w.WriteHeader(503)
				return
			}
			_ = p.Proxy(w, q, flows.New(release))
			return
		}
		if r.Proto == "HTTP/3.0" && r.Method == "CONNECT" {
			target := r.URL.Host
			if target == "" {
				target = r.Host
			}
			release, err := admission.Acquire(Identity(r))
			if err != nil {
				w.WriteHeader(503)
				return
			}
			tcpRelay.Relay(w, target, flows.New(release))
			return
		}
		if r.Proto == "HTTP/3.0" {
			w.WriteHeader(405)
		} else {
			w.WriteHeader(501)
		}
	})
	srv := &http3.Server{TLSConfig: http3.ConfigureTLSConfig(&metatls.Config{Certificates: []metatls.Certificate{cert}}), QUICConfig: qc, EnableDatagrams: true, MaxHeaderBytes: 64 * 1024, Handler: WithCredentials(h, creds)}
	if ready != nil {
		ready <- t.LocalAddr().String()
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeListener(ql) }()
	select {
	case e = <-serveErr:
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		flows.Close()
		_ = p.Close()
		tcpRelay.Close()
		_ = srv.Shutdown(shutdown)
		_ = srv.Close()
		_ = ql.Close()
		_ = qt.Close()
		_ = t.Close()
		select {
		case e = <-serveErr:
		case <-shutdown.Done():
			e = nil
		}
		if e != nil && !errors.Is(e, net.ErrClosed) && !errors.Is(e, mh.ErrServerClosed) {
			return e
		}
		return nil
	}
}

func maxOr(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}
