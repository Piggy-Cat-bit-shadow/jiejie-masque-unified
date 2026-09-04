package connectudp

import (
	"context"
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
	Policy  TargetPolicy
	mu      sync.Mutex
	closed  bool
	wg      sync.WaitGroup
	closers map[io.Closer]struct{}
}

const tcpCopyBufferSize = 32 << 10

var tcpCopyBufferPool = sync.Pool{New: func() any { return make([]byte, tcpCopyBufferSize) }}

func copyWithPool(dst io.Writer, src io.Reader) (int64, error) {
	buf := tcpCopyBufferPool.Get().([]byte)
	defer tcpCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func (r *TCPRelay) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.closers) / 2
}

func statusForDialError(err error) int {
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return 400
	}
	return 502
}

func (r *TCPRelay) Relay(w mh.ResponseWriter, target string, flow *Flow) {
	defer flow.Close()
	if target == "" {
		w.WriteHeader(400)
		return
	}
	resolved, err := r.Policy.ResolveTarget(context.Background(), "tcp", target)
	if err != nil {
		w.WriteHeader(statusForDialError(err))
		return
	}
	conn, err := net.DialTimeout("tcp", resolved, 10*time.Second)
	if err != nil {
		w.WriteHeader(statusForDialError(err))
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	flow.SetCloseResource(func() {
		_ = conn.Close()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = stream.Close()
	})
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
	go func() { _, _ = copyWithPool(activityWriter{Writer: conn, flow: flow}, stream); done <- struct{}{} }()
	go func() { _, _ = copyWithPool(activityWriter{Writer: stream, flow: flow}, conn); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	_ = stream.Close()
	<-done
}

type activityWriter struct {
	io.Writer
	flow *Flow
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.flow.Touch()
	}
	return n, err
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
