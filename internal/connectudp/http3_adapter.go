package connectudp

import (
	stdhttp "net/http"

	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
)

// http3HandlerAdapter is the narrow boundary between the legacy MetaCubeX
// handler surface used by the CONNECT-UDP implementation and quic-go 0.62's
// standard-library HTTP/3 handler surface.
type http3HandlerAdapter struct{ handler mh.Handler }

func (a http3HandlerAdapter) ServeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	req := &mh.Request{
		Method:        r.Method,
		URL:           r.URL,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        mh.Header(r.Header),
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Host:          r.Host,
		RemoteAddr:    r.RemoteAddr,
		RequestURI:    r.RequestURI,
	}
	req = req.WithContext(r.Context())
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		stdhttp.Error(w, "CONNECT-UDP requires an HTTP/3 stream", stdhttp.StatusInternalServerError)
		return
	}
	a.handler.ServeHTTP(http3ResponseWriter{ResponseWriter: w, streamer: streamer}, req)
}

type http3ResponseWriter struct {
	stdhttp.ResponseWriter
	streamer http3.HTTPStreamer
}

func (w http3ResponseWriter) Header() mh.Header { return mh.Header(w.ResponseWriter.Header()) }
func (w http3ResponseWriter) HTTPStream() *http3.Stream {
	if w.streamer == nil {
		return nil
	}
	return w.streamer.HTTPStream()
}
