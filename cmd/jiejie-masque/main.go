package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/packet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/tunnel"
	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
)

const tunnelMTU = 1280

func runConnectIPLegacy() {
	if err := serveConnectIP(); err != nil {
		log.Fatal(err)
	}
}

func serveConnectIP() error {
	return serveConnectIPArgs(os.Args[1:])
}

func serveConnectIPArgs(args []string) error {
	if len(args) > 0 && args[0] == "keygen" {
		keygen()
		return nil
	}
	if len(args) > 0 && args[0] == "server-keygen" {
		serverKeygen(args[1:])
		return nil
	}
	if len(args) > 0 && args[0] == "check-config" {
		fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
		path := fs.String("config", "/etc/masque-lite/config.yaml", "configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return checkConfig(*path)
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "/etc/masque-lite/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	log.Printf("build provenance main_commit=%s connect_ip_go_commit=%s quic_go_commit=%s build_time=%s go_version=%s", commit, connectIPGoCommit, quicGoCommit, buildTime, runtime.Version())
	serverAddresses, err := c.ServerAddresses()
	if err != nil {
		return err
	}
	clients, err := c.ResolvedClients()
	if err != nil {
		return err
	}
	byKey := make(map[string]config.ResolvedClient)
	for _, cl := range clients {
		byKey[cl.PublicKey] = cl
	}
	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return fmt.Errorf("exactly one client certificate required")
		}
		if _, ok := byKey[auth.PublicKeyBytes(cs.PeerCertificates[0])]; !ok {
			return fmt.Errorf("client certificate public key is not authorized")
		}
		return nil
	}
	tun, err := tunnel.Open("masque0", tunnelMTU)
	if err != nil {
		return err
	}
	defer tun.Close()
	log.Printf("CONNECT-IP TUN mode: plain mtu=%d", tunnelMTU)
	if err = tun.ConfigureAddresses(serverAddresses.Prefixes()); err != nil {
		return fmt.Errorf("configure masque0: %w", err)
	}
	packetConn, err := net.ListenPacket("udp", c.Listen)
	if err != nil {
		return err
	}
	defer packetConn.Close()
	mgr := session.NewManager(len(clients))
	fatal := make(chan error, 2)
	go tunDispatcher(tun, mgr, fatal)
	qc := &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 1}
	transport := &quic.Transport{Conn: packetConn}
	ql, err := transport.Listen(http3.ConfigureTLSConfig(tc), qc)
	if err != nil {
		return err
	}
	defer ql.Close()
	defer transport.Close()
	log.Printf("CONNECT-IP QUIC congestion controller: %s", c.QUIC.CongestionController)
	if serverAddresses.IPv6.IsValid() && !c.Server.AdvertiseIPv6DefaultRoute {
		log.Printf("IPv6 egress note: routed public egress is not advertised; ULA is suitable only for tunnel-local services, provider prefix routing is not verified locally")
	}
	if serverAddresses.IPv6.IsValid() && serverAddresses.IPv6.Bits() == 128 {
		log.Printf("IPv6 egress warning: server tunnel is configured as a single /128; a routed client prefix/provider return path is not established")
	}
	s := &http3.Server{TLSConfig: tc, QUICConfig: qc, EnableDatagrams: true, ConnContext: connectIPConnContext(c.QUIC.CongestionController), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, c, serverAddresses, byKey, mgr, tun)
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.ServeListener(ql) }()
	appCtx, stopDiagnostics := context.WithCancel(context.Background())
	defer stopDiagnostics()
	go connectIPDiagnostics(appCtx, mgr, tun)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	var runErr error
	select {
	case <-sig:
	case runErr = <-serveErr:
		if isServerClosed(runErr) {
			runErr = nil
		}
	case runErr = <-fatal:
		log.Printf("infrastructure fatal: %v", runErr)
	}
	for _, cl := range mgr.Snapshot() {
		cl.Close()
	}
	stopDiagnostics()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = s.Shutdown(ctx); err != nil {
		_ = s.Close()
	}
	return runErr
}

// connectIPDiagnostics emits identity-free, rate-limited dataplane counters.
// It is intentionally a periodic snapshot: packet-level logging would itself
// distort the WAN path being diagnosed.
func connectIPDiagnostics(ctx context.Context, mgr *session.Manager, tun *tunnel.Device) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var previousTun tunnel.Stats
	var previousRuntime session.AggregateRuntimeStats
	previousAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t := tun.Stats()
			q := mgr.AggregateRuntimeStats()
			elapsed := now.Sub(previousAt)
			if elapsed <= 0 {
				elapsed = 30 * time.Second
			}
			delta := func(current, previous uint64) uint64 { return counterDelta(current, previous) }
			mbps := func(n uint64) float64 { return rateMbps(n, elapsed) }
			log.Printf("CONNECT-IP: sessions=%d tun_rx_mbps=%.2f tun_tx_mbps=%.2f udp_wire_mbps=%.2f cc=%s cwnd=%d inflight=%d pacing=%d rtt=%s loss=%d spurious=%d bbr_mode=%s bbr_bw=%d bbr_target_cwnd=%d bbr_app_limited=%t gso_writes=%d gso_segments=%d",
				q.Connections, mbps(delta(t.RXBytes, previousTun.RXBytes)), mbps(delta(t.TXBytes, previousTun.TXBytes)),
				mbps(delta(q.UDPWireBytes, previousRuntime.UDPWireBytes)), q.CongestionController, q.CongestionWindows,
				q.BytesInFlight, q.PacingRate, q.SmoothedRTT, delta(q.PacketsLost, previousRuntime.PacketsLost),
				delta(q.SpuriousLosses, previousRuntime.SpuriousLosses), q.BBRMode, q.BBRBandwidthEstimate,
				q.BBRTargetCwnd, q.BBRAppLimited, delta(q.GSOMultiSegmentWrites, previousRuntime.GSOMultiSegmentWrites),
				delta(q.GSOSegmentsTotal, previousRuntime.GSOSegmentsTotal))
			previousTun, previousRuntime, previousAt = t, q, now
		}
	}
}

func counterDelta(now, before uint64) uint64 {
	if now < before {
		return now
	}
	return now - before
}

func rateMbps(bytes uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(bytes) * 8 / elapsed.Seconds() / 1e6
}

func isServerClosed(err error) bool {
	return errors.Is(err, stdhttp.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

func handleRequest(w http.ResponseWriter, r *http.Request, c config.Config, serverAddresses config.TunnelAddresses, byKey map[string]config.ResolvedClient, mgr *session.Manager, tun *tunnel.Device) {
	parseProtocol, ok := protocolForParse(r.Proto)
	if !ok {
		log.Printf("CONNECT-IP rejected: unsupported protocol %q", r.Proto)
		http.Error(w, "only CONNECT-IP is supported", http.StatusNotImplemented)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		log.Printf("CONNECT-IP rejected: missing client certificate")
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	client, ok := byKey[auth.PublicKeyBytes(r.TLS.PeerCertificates[0])]
	if !ok {
		log.Printf("CONNECT-IP rejected: unauthorized client")
		http.Error(w, "client certificate not authorized", http.StatusUnauthorized)
		return
	}
	template, err := requestTemplate(r.Host)
	if err != nil {
		log.Printf("CONNECT-IP rejected: invalid authority: %v", err)
		http.Error(w, "invalid authority", http.StatusBadRequest)
		return
	}
	copyReq := r.Clone(r.Context())
	copyReq.Proto = parseProtocol
	req, err := connectip.ParseRequest(copyReq, template)
	if err != nil {
		log.Printf("CONNECT-IP request parse failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conn, err := (&connectip.Proxy{}).Proxy(w, req)
	if err != nil {
		log.Printf("CONNECT-IP tunnel establishment failed: %v", err)
		return
	}
	clientAddresses := config.TunnelAddresses{IPv4: client.TunnelIPv4, IPv6: client.TunnelIPv6}
	if err = conn.AssignAddresses(r.Context(), clientAddresses.Prefixes()); err != nil {
		log.Printf("AssignAddresses failed: %v", err)
		conn.Close()
		return
	}
	if err = conn.AdvertiseRoute(r.Context(), connectIPRoutes(clientAddresses, serverAddresses, c.Server.AdvertiseIPv6DefaultRoute)); err != nil {
		log.Printf("AdvertiseRoute failed: %v", err)
		conn.Close()
		return
	}
	s := session.NewWithAddresses(r.Context(), clientAddresses.Addresses(), client.PublicKey, &connectIPPacketConn{Conn: conn}, nil)
	old, err := mgr.Replace(s)
	if err != nil {
		log.Printf("session registration failed: %v", err)
		s.Close()
		http.Error(w, "tunnel address unavailable", http.StatusConflict)
		return
	}
	if len(old) != 0 {
		log.Printf("session takeover")
	}
	log.Printf("CONNECT-IP session established")
	go sessionReaderWithAddresses(s, tun, serverAddresses)
	select {
	case <-r.Context().Done():
	case <-s.Ctx.Done():
	}
	s.Close()
	log.Printf("CONNECT-IP session closed")
}

// connectIPPacketConn adapts the clean upstream connect-ip-go packet API to
// the server's bounded buffer-oriented session interface.
type connectIPPacketConn struct{ *connectip.Conn }

func (c *connectIPPacketConn) ReadPacket(dst []byte) (int, error) {
	p, err := c.Conn.ReadPacket()
	if err != nil {
		return 0, err
	}
	if len(p) > len(dst) {
		return 0, fmt.Errorf("connect-ip packet exceeds session buffer: %d > %d", len(p), len(dst))
	}
	return copy(dst, p), nil
}

func (c *connectIPPacketConn) WritePacket(p []byte) ([]byte, error) { return c.Conn.WritePacket(p) }

func (c *connectIPPacketConn) RuntimeStats() quic.RuntimeStats { return quic.RuntimeStats{} }

func firstPrefix(a config.TunnelAddresses) netip.Prefix {
	if a.IPv4.IsValid() {
		return a.IPv4
	}
	return a.IPv6
}
func connectIPRoutes(client, server config.TunnelAddresses, advertiseIPv6DefaultRoute bool) []connectip.IPRoute {
	routes := make([]connectip.IPRoute, 0, 3)
	if client.IPv4.IsValid() {
		routes = append(routes, connectip.IPRoute{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")})
	}
	if client.IPv6.IsValid() {
		if advertiseIPv6DefaultRoute {
			routes = append(routes, connectip.IPRoute{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")})
		}
	}
	return routes
}

type tunPacketReader interface{ Read([]byte) (int, error) }
type tunPacketWriter interface{ Write([]byte) (int, error) }
type tunPacketDevice interface {
	tunPacketReader
	tunPacketWriter
}

func tunDispatcher(tun *tunnel.Device, mgr *session.Manager, fatal chan<- error) {
	buf := make([]byte, tunnelMTU)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			fatal <- fmt.Errorf("TUN dispatcher: %w", err)
			return
		}
		dispatchTUNPacket(buf[:n], mgr, tun)
	}
}

func dispatchTUNPacket(data []byte, mgr *session.Manager, tun tunPacketWriter) {
	dst, ok := packet.Destination(data)
	if !ok {
		return
	}
	s := mgr.Lookup(dst)
	if s == nil {
		return
	}
	icmp, err := s.Conn.WritePacket(data)
	if len(icmp) != 0 {
		if _, writeErr := tun.Write(icmp); writeErr != nil {
			s.Close()
			return
		}
	}
	if err != nil {
		if normalSessionError(err, s.Ctx) {
			return
		}
		log.Printf("CONNECT-IP packet write failed: %v", err)
		s.Close()
		return
	}
}

func sessionReaderWithAddresses(s *session.Session, tun tunPacketWriter, serverAddresses config.TunnelAddresses) {
	buf := make([]byte, tunnelMTU)
	for s.Ctx.Err() == nil {
		n, err := s.Conn.ReadPacket(buf)
		if err != nil {
			if normalSessionError(err, s.Ctx) {
				return
			}
			log.Printf("CONNECT-IP session read failed: %v", err)
			s.Close()
			return
		}
		pkt := buf[:n]
		if !prepareSessionPacket(pkt, s, serverAddresses) {
			continue
		}
		if _, err = tun.Write(pkt); err != nil {
			log.Printf("CONNECT-IP TUN write failed: %v", err)
			s.Close()
			return
		}
	}
}

func prepareSessionPacket(pkt []byte, s *session.Session, serverAddresses config.TunnelAddresses) bool {
	info, ok := packet.Parse(pkt)
	if !ok || !s.OwnsAddress(info.Source) {
		return false
	}
	dst := info.Destination
	if containsPrefix(serverAddresses, dst) {
		return false
	}
	select {
	case <-s.Ctx.Done():
		return false
	default:
	}
	return true
}

func containsPrefix(a config.TunnelAddresses, ip netip.Addr) bool {
	return (a.IPv4.IsValid() && a.IPv4.Contains(ip)) || (a.IPv6.IsValid() && a.IPv6.Contains(ip))
}
func protocolForParse(protocol string) (string, bool) {
	switch protocol {
	case "connect-ip":
		return "connect-ip", true
	default:
		return "", false
	}
}

func requestTemplate(host string) (*uritemplate.Template, error) {
	if host == "" {
		return nil, fmt.Errorf("empty authority")
	}
	u, err := neturl.Parse("https://" + host)
	if err != nil || u.User != nil || u.Host != host || u.Hostname() == "" {
		return nil, fmt.Errorf("malformed authority")
	}
	return uritemplate.New("https://" + host + "/connect-ip")
}

func normalSessionError(err error, ctx context.Context) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
