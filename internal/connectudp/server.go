package connectudp

import (
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
		if len(b) != 16 {
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
			return resetKey(path)
		}
		return nil, e
	}
	defer f.Close()
	if _, e = f.Write(k[:]); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	return &k, nil
}
func Serve(c Config) error {
	return ServeContext(context.Background(), c)
}
func ServeContext(ctx context.Context, c Config) error {
	user, pass, err := c.ResolveAuth()
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
	t, e := net.ListenUDP("udp", mustUDP(c.Listen))
	if e != nil {
		return e
	}
	qt := &quic.Transport{Conn: t, StatelessResetKey: rk}
	qc := &quic.Config{EnableDatagrams: true, KeepAlivePeriod: c.KeepAlive(), MaxIdleTimeout: c.IdleTimeout()}
	ql, e := qt.Listen(http3.ConfigureTLSConfig(&metatls.Config{Certificates: []metatls.Certificate{cert}}), qc)
	if e != nil {
		return e
	}
	u, e := uritemplate.New("https://" + c.PublicAuthority + "/.well-known/masque/udp/{target_host}/{target_port}/")
	if e != nil {
		return e
	}
	p := &Proxy{}
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
			_ = p.Proxy(w, q)
			return
		}
		if r.Proto == "HTTP/3.0" && r.Method == "CONNECT" {
			target := r.URL.Host
			if target == "" {
				target = r.Host
			}
			conn, e := net.DialTimeout("tcp", target, 10*time.Second)
			if e != nil {
				w.WriteHeader(502)
				return
			}
			defer conn.Close()
			s := w.(http3.HTTPStreamer).HTTPStream()
			w.WriteHeader(200)
			go func() { _, _ = io.Copy(conn, s); _ = conn.Close() }()
			_, _ = io.Copy(s, conn)
			return
		}
		if r.Proto == "HTTP/3.0" {
			w.WriteHeader(405)
		} else {
			w.WriteHeader(501)
		}
	})
	srv := &http3.Server{TLSConfig: http3.ConfigureTLSConfig(&metatls.Config{Certificates: []metatls.Certificate{cert}}), QUICConfig: qc, EnableDatagrams: true, Handler: WithAuth(h, user, pass)}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeListener(ql) }()
	select {
	case e = <-serveErr:
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = p.Close()
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
		if e != nil && !errors.Is(e, net.ErrClosed) {
			return e
		}
		return nil
	}
}
func mustUDP(s string) *net.UDPAddr {
	a, e := net.ResolveUDPAddr("udp", s)
	if e != nil {
		panic(e)
	}
	return a
}
