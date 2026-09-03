package connectudp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
)

func rcConfig(t *testing.T, total, perUser int) Config {
	c := integrationConfig(t)
	c.Auth.AllowUnauthenticated = false
	c.Auth.Users = []AuthUser{{Username: "user-a", Password: "password-a"}, {Username: "user-b", Password: "password-b"}, {Username: "user-c", Password: "password-c"}, {Username: "user-d", Password: "password-d"}}
	c.Limits.MaxActiveFlows, c.Limits.MaxActiveFlowsPerUser = total, perUser
	c.Limits.FlowIdleTimeout = "1h"
	return c
}

func startRCServer(t *testing.T, c Config) (string, *serverState, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errs := make(chan error, 1)
	state := &serverState{}
	go func() { errs <- serveContextWithState(ctx, c, ready, 10*time.Millisecond, state) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("server start timeout")
	}
	return addr, state, cancel, errs
}

func dialRC(t *testing.T, addr, user, password string) *http3.ClientConn {
	cc := dialH3(t, addr)
	return cc
}

func authHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func openRCUDP(t *testing.T, cc *http3.ClientConn, target, user, password string) (*http3.RequestStream, error) {
	status, str, err := openRCUDPStatus(t, cc, target, user, password)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		_ = str.Close()
		return nil, fmt.Errorf("udp status %d", status)
	}
	return str, nil
}

func openRCUDPStatus(t *testing.T, cc *http3.ClientConn, target, user, password string) (int, *http3.RequestStream, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return 0, nil, err
	}
	port := target[strings.LastIndex(target, ":")+1:]
	req := &mh.Request{Method: "CONNECT", Proto: "connect-udp", Host: "proxy.test", URL: &url.URL{Scheme: "https", Host: "proxy.test", Path: "/.well-known/masque/udp/127.0.0.1/" + port + "/"}, Header: make(mh.Header)}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if user != "" || password != "" {
		req.Header.Set("Authorization", authHeader(user, password))
	}
	if err := str.SendRequestHeader(req); err != nil {
		return 0, nil, err
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return 0, nil, err
	}
	return rsp.StatusCode, str, nil
}

func openRCTCP(t *testing.T, cc *http3.ClientConn, target, user, password string) (*http3.RequestStream, error) {
	status, str, err := openRCTCPStatus(t, cc, target, user, password)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		_ = str.Close()
		return nil, fmt.Errorf("tcp status %d", status)
	}
	return str, nil
}

func openRCTCPStatus(t *testing.T, cc *http3.ClientConn, target, user, password string) (int, *http3.RequestStream, error) {
	t.Helper()
	str, err := cc.OpenRequestStream(context.Background())
	if err != nil {
		return 0, nil, err
	}
	req := &mh.Request{Method: "CONNECT", Host: target, URL: &url.URL{Host: target}, Header: make(mh.Header)}
	if user != "" || password != "" {
		req.Header.Set("Authorization", authHeader(user, password))
	}
	if err := str.SendRequestHeader(req); err != nil {
		return 0, nil, err
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return 0, nil, err
	}
	return rsp.StatusCode, str, nil
}

func startRCEchoes(t *testing.T) (string, string) {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Close() })
	go func() {
		b := make([]byte, 1600)
		for {
			n, a, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = u.WriteToUDP(b[:n], a)
		}
	}()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return u.LocalAddr().String(), tcp.Addr().String()
}

func eventuallyRC(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func TestFourUserRealHTTP3SmokeAndIsolation(t *testing.T) {
	c := rcConfig(t, 32, 8)
	addr, state, cancel, errs := startRCServer(t, c)
	defer func() {
		cancel()
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}()
	udpTarget, tcpTarget := startRCEchoes(t)
	users := []string{"user-a", "user-b", "user-c", "user-d"}
	var wg sync.WaitGroup
	for _, user := range users {
		user := user
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc := dialRC(t, addr, user, "password-"+user[len(user)-1:])
			us, err := openRCUDP(t, cc, udpTarget, user, "password-"+user[len(user)-1:])
			if err != nil {
				t.Error(err)
				return
			}
			p, _ := buildContextDatagram([]byte("udp-" + user))
			if err = us.SendDatagram(p); err != nil {
				t.Error(err)
			}
			ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			got, err := us.ReceiveDatagram(ctx)
			if err != nil || !strings.Contains(string(got), user) {
				t.Errorf("udp %s: %q %v", user, got, err)
			}
			_ = us.Close()
			ts, err := openRCTCP(t, cc, tcpTarget, user, "password-"+user[len(user)-1:])
			if err != nil {
				t.Error(err)
				return
			}
			for _, p := range []string{"tcp-" + user + "-1", "tcp-" + user + "-2"} {
				if _, err = ts.Write([]byte(p)); err != nil {
					t.Error(err)
					break
				}
				got := make([]byte, len(p))
				if _, err = io.ReadFull(ts, got); err != nil || string(got) != p {
					t.Errorf("tcp %s: %q %v", user, got, err)
				}
			}
			_ = ts.Close()
		}()
	}
	wg.Wait()
	eventuallyRC(t, time.Second, func() bool {
		total, users := state.admission.Counts()
		return total == 0 && len(users) == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
	})
}

func TestRealH3CapacityAndRecovery(t *testing.T) {
	c := rcConfig(t, 8, 2)
	addr, state, cancel, errs := startRCServer(t, c)
	udpTarget, _ := startRCEchoes(t)
	cc1 := dialRC(t, addr, "user-a", "password-a")
	a1, err := openRCUDP(t, cc1, udpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	cc2 := dialRC(t, addr, "user-a", "password-a")
	a2, err := openRCUDP(t, cc2, udpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = openRCUDP(t, cc2, udpTarget, "user-a", "password-a"); err == nil {
		t.Fatal("per-user H3 cap was not enforced")
	}
	b := dialRC(t, addr, "user-b", "password-b")
	b1, err := openRCUDP(t, b, udpTarget, "user-b", "password-b")
	if err != nil {
		t.Fatal("other user blocked: " + err.Error())
	}
	_ = a1.Close()
	_ = cc1.CloseWithError(0, "capacity test")
	eventuallyRC(t, time.Second, func() bool { return state.admission.countsTotal() == 2 })
	cc3 := dialRC(t, addr, "user-a", "password-a")
	a3, err := openRCUDP(t, cc3, udpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal("per-user capacity did not recover: " + err.Error())
	}
	_ = a2.Close()
	_ = a3.Close()
	_ = b1.Close()
	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	eventuallyRC(t, time.Second, func() bool {
		return state.flows.Count() == 0 && state.relay.activeCount() == 0 && state.admission.countsTotal() == 0
	})
}

func TestRealH3GlobalCapacityRecovery(t *testing.T) {
	c := rcConfig(t, 4, 4)
	addr, state, cancel, errs := startRCServer(t, c)
	udpTarget, _ := startRCEchoes(t)
	cc := dialRC(t, addr, "user-a", "password-a")
	flows := make([]*http3.RequestStream, 0, 4)
	conns := make([]*http3.ClientConn, 0, 4)
	for i := 0; i < 4; i++ {
		if i > 0 {
			cc = dialRC(t, addr, "user-a", "password-a")
		}
		conns = append(conns, cc)
		f, err := openRCUDP(t, cc, udpTarget, "user-a", "password-a")
		if err != nil {
			t.Fatal(err)
		}
		flows = append(flows, f)
	}
	if _, err := openRCUDP(t, cc, udpTarget, "user-b", "password-b"); err == nil {
		t.Fatal("global H3 cap was not enforced")
	}
	_ = flows[0].Close()
	_ = conns[0].CloseWithError(0, "capacity test")
	eventuallyRC(t, time.Second, func() bool { return state.admission.countsTotal() == 3 })
	f, err := openRCUDP(t, cc, udpTarget, "user-b", "password-b")
	if err != nil {
		t.Fatal("global capacity did not recover: " + err.Error())
	}
	_ = f.Close()
	for _, f := range flows[1:] {
		_ = f.Close()
	}
	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestRealH3RestartReusesResetKey(t *testing.T) {
	c := rcConfig(t, 8, 8)
	addr, state, cancel, errs := startRCServer(t, c)
	udpTarget, tcpTarget := startRCEchoes(t)
	cc := dialRC(t, addr, "user-a", "password-a")
	udp, err := openRCUDP(t, cc, udpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := buildContextDatagram([]byte("before-restart"))
	if err = udp.SendDatagram(p); err != nil {
		t.Fatal(err)
	}
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if _, err = udp.ReceiveDatagram(ctx); err != nil {
		t.Fatal(err)
	}
	tcp, err := openRCTCP(t, cc, tcpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("before-restart-tcp")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("before-restart-tcp"))
	if _, err = io.ReadFull(tcp, got); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	key1, err := os.ReadFile(c.QUIC.StatelessResetKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = <-errs; err != nil {
		t.Fatal(err)
	}
	eventuallyRC(t, time.Second, func() bool {
		return state.flows.Count() == 0 && state.relay.activeCount() == 0 && state.admission.countsTotal() == 0
	})
	key2, err := os.ReadFile(c.QUIC.StatelessResetKeyFile)
	if err != nil || !bytes.Equal(key1, key2) {
		t.Fatalf("reset key changed: %v", err)
	}
	addr, state, cancel, errs = startRCServer(t, c)
	cc = dialRC(t, addr, "user-a", "password-a")
	udp, err = openRCUDP(t, cc, udpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	p, _ = buildContextDatagram([]byte("after-restart"))
	if err = udp.SendDatagram(p); err != nil {
		t.Fatal(err)
	}
	ctx, done = context.WithTimeout(context.Background(), time.Second)
	defer done()
	if _, err = udp.ReceiveDatagram(ctx); err != nil {
		t.Fatal(err)
	}
	_ = udp.Close()
	tcp, err = openRCTCP(t, cc, tcpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("after-restart-tcp")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len("after-restart-tcp"))
	if _, err = io.ReadFull(tcp, got); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	cancel()
	if err = <-errs; err != nil {
		t.Fatal(err)
	}
	eventuallyRC(t, time.Second, func() bool {
		return state.flows.Count() == 0 && state.relay.activeCount() == 0 && state.admission.countsTotal() == 0
	})
}

func TestRealH3ReconnectAndAbruptClose(t *testing.T) {
	c := rcConfig(t, 16, 8)
	addr, state, cancel, errs := startRCServer(t, c)
	udpTarget, tcpTarget := startRCEchoes(t)
	for i := 0; i < 10; i++ {
		cc := dialRC(t, addr, "user-a", "password-a")
		flow, err := openRCUDP(t, cc, udpTarget, "user-a", "password-a")
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte(fmt.Sprintf("udp-reconnect-%d", i))
		packet, _ := buildContextDatagram(payload)
		if err = flow.SendDatagram(packet); err != nil {
			t.Fatal(err)
		}
		ctx, done := context.WithTimeout(context.Background(), time.Second)
		_, err = flow.ReceiveDatagram(ctx)
		done()
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			_ = cc.CloseWithError(0, "abrupt test")
		} else {
			_ = flow.Close()
			_ = cc.CloseWithError(0, "graceful test")
		}
	}
	for i := 0; i < 10; i++ {
		cc := dialRC(t, addr, "user-b", "password-b")
		flow, err := openRCTCP(t, cc, tcpTarget, "user-b", "password-b")
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte(fmt.Sprintf("tcp-reconnect-%d", i))
		if _, err = flow.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(flow, got); err != nil || string(got) != string(payload) {
			t.Fatalf("tcp roundtrip %d: %q %v", i, got, err)
		}
		if i%2 == 0 {
			_ = cc.CloseWithError(0, "abrupt test")
		} else {
			_ = flow.Close()
			_ = cc.CloseWithError(0, "graceful test")
		}
	}
	eventuallyRC(t, 2*time.Second, func() bool {
		return state.flows.Count() == 0 && state.relay.activeCount() == 0 && state.admission.countsTotal() == 0
	})
	cancel()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestRealH3AuthenticationFailures(t *testing.T) {
	c := rcConfig(t, 8, 8)
	addr, state, cancel, errs := startRCServer(t, c)
	defer func() {
		cancel()
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}()
	udpTarget, tcpTarget := startRCEchoes(t)

	t.Run("wrong-password", func(t *testing.T) {
		cc := dialRC(t, addr, "user-a", "wrong-password")
		status, str, err := openRCUDPStatus(t, cc, udpTarget, "user-a", "wrong-password")
		if err != nil {
			t.Fatal(err)
		}
		_ = str.Close()
		if status != 407 {
			t.Fatalf("wrong-password status = %d, want 407", status)
		}
		_ = cc.CloseWithError(0, "auth failure")
		eventuallyRC(t, time.Second, func() bool {
			return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
		})
	})

	t.Run("unknown-user", func(t *testing.T) {
		cc := dialRC(t, addr, "unknown-user", "password")
		status, str, err := openRCTCPStatus(t, cc, tcpTarget, "unknown-user", "password")
		if err != nil {
			t.Fatal(err)
		}
		_ = str.Close()
		if status != 407 {
			t.Fatalf("unknown-user status = %d, want 407", status)
		}
		_ = cc.CloseWithError(0, "auth failure")
		eventuallyRC(t, time.Second, func() bool {
			return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
		})
	})

	t.Run("no-auth", func(t *testing.T) {
		cc := dialRC(t, addr, "", "")
		status, str, err := openRCTCPStatus(t, cc, tcpTarget, "", "")
		if err != nil {
			t.Fatal(err)
		}
		_ = str.Close()
		if status != 407 {
			t.Fatalf("no-auth status = %d, want 407", status)
		}
		_ = cc.CloseWithError(0, "auth failure")
		eventuallyRC(t, time.Second, func() bool {
			return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
		})
	})

	cc := dialRC(t, addr, "user-b", "password-b")
	udp, err := openRCUDP(t, cc, udpTarget, "user-b", "password-b")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := buildContextDatagram([]byte("auth-recovery-udp"))
	if err = udp.SendDatagram(p); err != nil {
		t.Fatal(err)
	}
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	if _, err = udp.ReceiveDatagram(ctx); err != nil {
		done()
		t.Fatal(err)
	}
	done()
	_ = udp.Close()
	tcp, err := openRCTCP(t, cc, tcpTarget, "user-b", "password-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("auth-recovery-tcp")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("auth-recovery-tcp"))
	if _, err = io.ReadFull(tcp, got); err != nil || string(got) != "auth-recovery-tcp" {
		t.Fatalf("auth recovery TCP: %q %v", got, err)
	}
	_ = tcp.Close()
	_ = cc.CloseWithError(0, "auth recovery complete")
	eventuallyRC(t, time.Second, func() bool {
		return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
	})
}

func TestRealH3TCPRefusedAndRecovery(t *testing.T) {
	c := rcConfig(t, 8, 8)
	addr, state, cancel, errs := startRCServer(t, c)
	defer func() {
		cancel()
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedTarget := closed.Addr().String()
	_ = closed.Close()
	cc := dialRC(t, addr, "user-a", "password-a")
	status, str, err := openRCTCPStatus(t, cc, closedTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	if status != 502 {
		t.Fatalf("refused status = %d, want 502", status)
	}
	_ = cc.CloseWithError(0, "refused target")
	eventuallyRC(t, time.Second, func() bool {
		return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
	})

	_, tcpTarget := startRCEchoes(t)
	cc = dialRC(t, addr, "user-a", "password-a")
	tcp, err := openRCTCP(t, cc, tcpTarget, "user-a", "password-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("refused-recovery")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("refused-recovery"))
	if _, err = io.ReadFull(tcp, got); err != nil || string(got) != "refused-recovery" {
		t.Fatalf("refused recovery TCP: %q %v", got, err)
	}
	_ = tcp.Close()
	_ = cc.CloseWithError(0, "recovery complete")
	eventuallyRC(t, time.Second, func() bool {
		return state.admission.countsTotal() == 0 && state.flows.Count() == 0 && state.relay.activeCount() == 0
	})
}

func (a *Admission) countsTotal() int { n, _ := a.Counts(); return n }
