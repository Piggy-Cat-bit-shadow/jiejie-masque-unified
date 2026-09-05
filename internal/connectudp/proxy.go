package connectudp

import (
	"context"
	"errors"
	mh "github.com/metacubex/http"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
)

const maxUDPPayloadSize = 1500

var contextIDZero = quicvarint.Append([]byte{}, 0)

func parseContextDatagram(data []byte) ([]byte, bool, error) {
	id, n, err := quicvarint.Parse(data)
	if err != nil {
		return nil, false, err
	}
	if id != 0 || len(data[n:]) > maxUDPPayloadSize {
		return nil, false, nil
	}
	return data[n:], true, nil
}

func buildContextDatagram(payload []byte) ([]byte, bool) {
	if len(payload) > maxUDPPayloadSize {
		return nil, false
	}
	b := make([]byte, 0, len(contextIDZero)+len(payload))
	b = append(b, contextIDZero...)
	b = append(b, payload...)
	return b, true
}

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

type datagramSender interface {
	SendDatagram([]byte) error
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	Policy    TargetPolicy
	mx        sync.Mutex
	closed    bool
	refCount  sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers   map[io.Closer]struct{}
	ownedPool *udpOwnedDatagramPool
	oversized oversizedDatagramLogger
}

func (s *Proxy) sharedOwnedPoolLocked() *udpOwnedDatagramPool {
	if s.ownedPool == nil {
		s.ownedPool = newUDPOwnedDatagramPool()
	}
	return s.ownedPool
}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Consistent with RFC 9209 Section 2.3.1.
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		// Recommended by RFC 9209 Section 2.3.2.
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			// "Negative response" isn't a real RCODE, but it is included
			// in RFC 8499 Section 3 as a sort of meta/pseudo-RCODE like NODATA,
			// and this section is referenced by the definition of the "rcode"
			// parameter.
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			// DNS intermediaries normally convert miscellaneous errors to SERVFAIL.
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w mh.ResponseWriter, r *ProxyRequest, flow *Flow) error {
	return s.ProxyContext(context.Background(), w, r, flow)
}

func (s *Proxy) ProxyContext(ctx context.Context, w mh.ResponseWriter, r *ProxyRequest, flow *Flow) error {
	defer flow.Close()
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

	proxyStatus := httpsfv.NewItem(r.Host)
	// Adds a protocol-safe proxy status to the response. Raw network errors and
	// resolved next-hop addresses are deliberately not exposed: they can reveal
	// internal DNS and network topology to a proxy client.
	writeProxyStatus := func(err error) error {
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		return err
	}

	conn, err := s.Policy.DialUDP(ctx, r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		} else {
			proxyStatus.Params.Add("error", "destination_ip_unroutable")
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	if err = writeProxyStatus(nil); err != nil {
		w.WriteHeader(errToStatus(err))
		return err
	}
	return s.ProxyConnectedSocket(w, r, conn, flow)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w mh.ResponseWriter, _ *ProxyRequest, conn *net.UDPConn, flow *Flow) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	ownedPool := s.sharedOwnedPoolLocked()

	str := w.(http3.HTTPStreamer).HTTPStream()
	entry := proxyEntry{str: str, conn: conn}
	flow.SetCloseResource(func() { _ = entry.Close() })

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.proxyConnSend(conn, str, flow); err != nil {
			log.Printf("proxying send side failed: %v", err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str, flow, ownedPool); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side failed: %v", err)
			}
		}
		str.Close()
	}()
	// discard all capsules sent on the request stream
	if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("reading from request stream failed: %v", err)
	}
	str.Close()
	conn.Close()
	wg.Wait()
	s.mx.Lock()
	delete(s.closers, entry)
	s.mx.Unlock()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str *http3.Stream, flow *Flow) error {
	for {
		buffer, err := str.ReceiveDatagramBuffer(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		payload, ok, err := parseContextDatagram(buffer.Data)
		if err != nil {
			buffer.Release()
			return err
		}
		if !ok {
			buffer.Release()
			continue
		}
		if _, err := conn.Write(payload); err != nil {
			buffer.Release()
			return err
		}
		buffer.Release()
		flow.Touch()
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream, flow *Flow, ownedPool *udpOwnedDatagramPool) error {
	for {
		buffer := ownedPool.Acquire()
		// Read maxUDPPayloadSize+1 bytes: UDP Read reports the truncated
		// length, so the extra byte is the sentinel that distinguishes an
		// oversized packet without requiring ReadMsgUDP.
		n, err := conn.Read(buffer.data[udpPayloadOffset : udpPayloadOffset+maxUDPPayloadSize+1])
		if err != nil {
			buffer.Release()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUDPPayloadSize {
			buffer.Release()
			if count, ok := s.oversized.Record(time.Now()); ok {
				log.Printf("CONNECT-UDP dropped oversized UDP datagrams: count=%d", count)
			}
			continue
		}
		buffer.data[udpContextIDOffset] = 0
		if err := sendDatagramBufferOwnedOrDrop(str, buffer.data, udpContextIDOffset, len(contextIDZero)+n, buffer); err != nil {
			return err
		}
		flow.Touch()
	}
}

// sendDatagramOrDrop keeps a transient path-MTU reduction from terminating an
// otherwise healthy UDP flow.
func sendDatagramOrDrop(str datagramSender, packet []byte) error {
	err := str.SendDatagram(packet)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return nil
	}
	return err
}

type ownedDatagramSender interface {
	SendDatagramBufferOwned([]byte, int, int, quic.DatagramPayloadOwner) error
}

// sendDatagramBufferOwnedOrDrop releases the buffer when the send is rejected.
// A nil error transfers ownership to the QUIC connection.
func sendDatagramBufferOwnedOrDrop(str ownedDatagramSender, buf []byte, offset, length int, owner quic.DatagramPayloadOwner) error {
	err := str.SendDatagramBufferOwned(buf, offset, length, owner)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		owner.Release()
		return nil
	}
	if err != nil {
		owner.Release()
	}
	return err
}

// Close closes the proxy, immediately terminating all proxied flows.
func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return errors.Join(errs...)
}
