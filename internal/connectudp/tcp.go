package connectudp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

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

type tcpCopyDirection uint8

const (
	tcpClientToTarget tcpCopyDirection = iota
	tcpTargetToClient
)

type tcpCopyResult struct {
	direction tcpCopyDirection
	err       error
}

var tcpCopyBufferPool = sync.Pool{New: func() any { return make([]byte, tcpCopyBufferSize) }}

func copyWithPool(dst io.Writer, src io.Reader) (int64, error) {
	buf := tcpCopyBufferPool.Get().([]byte)
	defer tcpCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func closeWrite(conn io.Writer) error {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("TCP target does not support half-close")
	}
	return cw.CloseWrite()
}

func (r *TCPRelay) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.closers) / 2
}

func statusForDialError(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return 504
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 504
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return 400
	}
	return 502
}

func (r *TCPRelay) Relay(w mh.ResponseWriter, target string, flow *Flow) {
	r.RelayContext(context.Background(), w, target, flow)
}

func (r *TCPRelay) RelayContext(ctx context.Context, w mh.ResponseWriter, target string, flow *Flow) {
	defer flow.Close()
	if target == "" {
		w.WriteHeader(400)
		return
	}
	conn, err := r.Policy.DialTCP(ctx, target)
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
		r.hardClose(conn, stream)
		r.mu.Lock()
		delete(r.closers, conn)
		delete(r.closers, stream)
		r.mu.Unlock()
		r.wg.Done()
	}()
	w.WriteHeader(200)
	results := make(chan tcpCopyResult, 2)
	go func() {
		_, err := copyWithPool(activityWriter{Writer: conn, flow: flow}, stream)
		results <- tcpCopyResult{direction: tcpClientToTarget, err: err}
	}()
	go func() {
		_, err := copyWithPool(activityWriter{Writer: stream, flow: flow}, conn)
		results <- tcpCopyResult{direction: tcpTargetToClient, err: err}
	}()

	first := <-results
	if first.err != nil {
		r.hardClose(conn, stream)
		<-results
		return
	}
	switch first.direction {
	case tcpClientToTarget:
		if err := closeWrite(conn); err != nil {
			r.hardClose(conn, stream)
			<-results
			return
		}
	case tcpTargetToClient:
		_ = stream.Close()
	}
	second := <-results
	if second.err != nil {
		r.hardClose(conn, stream)
	}
}

func (r *TCPRelay) hardClose(conn net.Conn, stream *http3.Stream) {
	_ = conn.Close()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	_ = stream.Close()
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
