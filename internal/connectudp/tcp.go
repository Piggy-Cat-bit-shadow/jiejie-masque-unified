package connectudp

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
)

type TCPRelay struct {
	mu      sync.Mutex
	closed  bool
	wg      sync.WaitGroup
	closers map[io.Closer]struct{}
}

func statusForDialError(err error) int {
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return 400
	}
	return 502
}

func (r *TCPRelay) Relay(w mh.ResponseWriter, target string) {
	if target == "" {
		w.WriteHeader(400)
		return
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		w.WriteHeader(statusForDialError(err))
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = conn.Close()
		w.WriteHeader(503)
		return
	}
	if r.closers == nil {
		r.closers = make(map[io.Closer]struct{})
	}
	r.closers[conn] = struct{}{}
	r.closers[stream] = struct{}{}
	r.wg.Add(1)
	r.mu.Unlock()
	defer func() {
		_ = conn.Close()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = stream.Close()
		r.mu.Lock()
		delete(r.closers, conn)
		delete(r.closers, stream)
		r.mu.Unlock()
		r.wg.Done()
	}()
	w.WriteHeader(200)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, conn); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	_ = stream.Close()
	<-done
}

func (r *TCPRelay) Close() {
	r.mu.Lock()
	r.closed = true
	for c := range r.closers {
		if stream, ok := c.(*http3.Stream); ok {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}
