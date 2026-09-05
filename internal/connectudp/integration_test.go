package connectudp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	metatls "github.com/metacubex/tls"
)

func integrationConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = certFile.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = keyFile.Close()
	var c Config
	c.Mode = "connect-udp"
	c.Auth.AllowUnauthenticated = true
	c.TargetPolicy.AllowPrivate = true // loopback test origin; production defaults deny it.
	c.Listen = "127.0.0.1:0"
	c.PublicAuthority = "proxy.test"
	c.TLS.Cert = certPath
	c.TLS.Key = keyPath
	c.QUIC.StatelessResetKeyFile = filepath.Join(dir, "reset.key")
	return c
}

func startIntegrationServer(t *testing.T) (Config, string, func()) {
	t.Helper()
	c := integrationConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- serveContext(ctx, c, ready) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("server start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server start timeout")
	}
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("server shutdown: %v", err)
				}
			case <-time.After(4 * time.Second):
				t.Error("server shutdown timeout")
			}
		})
	}
	t.Cleanup(shutdown)
	return c, addr, shutdown
}

func dialH3(t *testing.T, addr string) *http3.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := quic.Dial(ctx, local, remote, &metatls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	tr := http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(conn)
	t.Cleanup(func() { _ = cc.CloseWithError(0, "") })
	return cc
}

func TestHTTP3ConnectUDPLoopback(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 1600)
		n, a, e := echo.ReadFromUDP(b)
		if e == nil {
			_, _ = echo.WriteToUDP(b[:n], a)
		}
	}()
	cc := dialH3(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := echo.LocalAddr().String()
	u := &url.URL{Scheme: "https", Host: "proxy.test", Path: "/.well-known/masque/udp/127.0.0.1/" + target[strings.LastIndex(target, ":")+1:] + "/"}
	req := &mh.Request{Method: "CONNECT", Proto: "connect-udp", Host: "proxy.test", URL: u, Header: make(mh.Header)}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if err = str.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	rsp, err := str.ReadResponse()
	if err != nil || rsp.StatusCode != 200 {
		t.Fatalf("response: %v %v", rsp, err)
	}
	payload := []byte("udp-loopback")
	packet, ok := buildContextDatagram(payload)
	if !ok {
		t.Fatal("packet")
	}
	if err = str.SendDatagram(packet); err != nil {
		t.Fatal(err)
	}
	got, err := str.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out, ok, err := parseContextDatagram(got)
	if err != nil || !ok || string(out) != string(payload) {
		t.Fatalf("roundtrip: %q %v", out, err)
	}
	shutdown()
}

func TestHTTP3TCPConnectLoopback(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	cc := dialH3(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := echo.Addr().String()
	req := &mh.Request{Method: "CONNECT", Host: target, URL: &url.URL{Host: target}}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	rsp, err := str.ReadResponse()
	if err != nil || rsp.StatusCode != 200 {
		t.Fatalf("response: %v %v", rsp, err)
	}
	for _, payload := range [][]byte{[]byte("message-one"), []byte("message-two")} {
		if _, err := str.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(str, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(payload) {
			t.Fatalf("roundtrip: %q", got)
		}
	}
	shutdown()
}

func TestHTTP3TCPClientHalfCloseReceivesTrailingResponse(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != "request-body" {
			err = fmt.Errorf("target request = %q", request)
		}
		if err == nil {
			_, err = conn.Write([]byte("trailing-response"))
		}
		if tcp, ok := conn.(*net.TCPConn); ok && err == nil {
			err = tcp.CloseWrite()
		}
		targetDone <- err
	}()

	cc := dialH3(t, addr)
	stream, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(&mh.Request{Method: "CONNECT", Host: target.Addr().String(), URL: &url.URL{Host: target.Addr().String()}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response: %v %v", response, err)
	}
	if _, err := stream.Write([]byte("request-body")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil || string(got) != "trailing-response" {
		t.Fatalf("trailing response = %q, err=%v", got, err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	shutdown()
}

func TestHTTP3TCPTargetHalfCloseKeepsClientDirection(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	clientData := make(chan string, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			clientData <- "accept error: " + err.Error()
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("target-response"))
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		data, readErr := io.ReadAll(conn)
		if readErr != nil {
			clientData <- "read error: " + readErr.Error()
			return
		}
		clientData <- string(data)
	}()

	cc := dialH3(t, addr)
	stream, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(&mh.Request{Method: "CONNECT", Host: target.Addr().String(), URL: &url.URL{Host: target.Addr().String()}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response: %v %v", response, err)
	}
	got := make([]byte, len("target-response"))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != "target-response" {
		t.Fatalf("target response = %q, err=%v", got, err)
	}
	if _, err := stream.Write([]byte("late-client-data")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-clientData; got != "late-client-data" {
		t.Fatalf("target received = %q", got)
	}
	shutdown()
}

func TestHTTP3TCPTargetResetTearsDownRelay(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}()

	cc := dialH3(t, addr)
	stream, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(&mh.Request{Method: "CONNECT", Host: target.Addr().String(), URL: &url.URL{Host: target.Addr().String()}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response: %v %v", response, err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := io.Copy(io.Discard, stream)
		readDone <- readErr
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("target reset did not tear down relay")
	}
	shutdown()
}

func TestHTTP3TCPClientResetTearsDownRelay(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan struct{})
	go func() {
		conn, err := target.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
		close(targetDone)
	}()

	cc := dialH3(t, addr)
	stream, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(&mh.Request{Method: "CONNECT", Host: target.Addr().String(), URL: &url.URL{Host: target.Addr().String()}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response: %v %v", response, err)
	}
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeConnectError))
	select {
	case <-targetDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client reset did not tear down target")
	}
	shutdown()
}

func TestHTTP3TCPHalfClosedShutdown(t *testing.T) {
	_, addr, shutdown := startIntegrationServer(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetReady := make(chan struct{})
	targetDone := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		_, err = io.ReadAll(conn)
		if err != nil {
			targetDone <- err
			return
		}
		close(targetReady)
		_, err = conn.Read(make([]byte, 1))
		targetDone <- err
	}()

	cc := dialH3(t, addr)
	stream, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(&mh.Request{Method: "CONNECT", Host: target.Addr().String(), URL: &url.URL{Host: target.Addr().String()}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response: %v %v", response, err)
	}
	if _, err := stream.Write([]byte("half-closed")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-targetReady:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not observe client FIN")
	}
	shutdown()
	select {
	case <-targetDone:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not unblock half-closed target")
	}
}
