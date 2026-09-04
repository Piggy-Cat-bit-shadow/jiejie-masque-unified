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
	"sync/atomic"
	"syscall"
	"time"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/dnsgateway"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/hostnet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/notify"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/packet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/quicstate"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/tunnel"
	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
)

var lastQueueOverflowLog atomic.Int64

func runConnectIPLegacy() {
	if err := serveConnectIP(); err != nil {
		log.Fatal(err)
	}
}

func serveConnectIP() error {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "server-keygen" {
		serverKeygen(os.Args[2:])
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "check-config" {
		fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
		path := fs.String("config", "/etc/masque-lite/config.yaml", "configuration file")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		return checkConfig(*path)
	}
	path := flag.String("config", "/etc/masque-lite/config.yaml", "configuration file")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if err := hostnet.CheckIPv4Forwarding(); err != nil {
		return err
	}
	resetKey, err := quicstate.LoadOrCreate(c.QUIC.StatelessResetKeyFile)
	if err != nil {
		return err
	}
	clients, err := c.ResolvedClients()
	if err != nil {
		return err
	}
	for i := range clients {
		if clients[i].Name == "" {
			// This name is only an in-memory session key.  Do not derive it
			// from the client's public key: it can otherwise turn up in logs.
			clients[i].Name = fmt.Sprintf("client-%d", i+1)
		}
	}
	byKey := make(map[string]config.ResolvedClient)
	for _, cl := range clients {
		for _, key := range cl.PublicKeys {
			byKey[key] = cl
		}
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
	serverPrefix, _ := netip.ParsePrefix(c.Server.TunnelIPv4)
	tun, err := tunnel.Open("masque0", c.Server.MTU)
	if err != nil {
		return err
	}
	defer tun.Close()
	if err = tun.Configure(serverPrefix); err != nil {
		return fmt.Errorf("configure masque0: %w", err)
	}
	var dnsGateway *dnsgateway.Gateway
	if c.DNSGateway.IsEnabled() {
		dnsTimeout, _ := time.ParseDuration(c.DNSGateway.Timeout)
		dnsGateway, err = dnsgateway.Start(dnsgateway.Config{
			ListenAddr: serverPrefix.Addr(), Port: c.DNSGateway.Port, Upstream: c.DNSGateway.Upstream,
			Timeout: dnsTimeout, Concurrency: c.DNSGateway.Concurrency,
		})
		if err != nil {
			return fmt.Errorf("start tunnel DNS gateway: %w", err)
		}
		defer dnsGateway.Close()
	}
	packetConn, err := net.ListenPacket("udp", c.Listen)
	if err != nil {
		return err
	}
	defer packetConn.Close()
	var mgr *session.Manager
	if c.Server.SessionNat.Enabled {
		pool, _ := netip.ParsePrefix(c.Server.SessionNat.Pool)
		excluded := make([]netip.Addr, 0, len(clients)+1)
		excluded = append(excluded, serverPrefix.Addr())
		for _, cl := range clients {
			excluded = append(excluded, cl.TunnelIPv4.Addr())
		}
		reuseDelay, _ := time.ParseDuration(c.Server.SessionNat.ReuseDelay)
		mgr = session.NewShadowManagerWithClock(pool, c.Server.SessionNat.MaxSessions, excluded, reuseDelay, time.Now, nil)
		mgr.SetMaxSessionsPerClient(c.Server.SessionNat.MaxSessionsPerClient)
		log.Printf("shared-session NAT enabled: max_sessions=%d", c.Server.SessionNat.MaxSessions)
	} else {
		mgr = session.NewManager()
	}
	if mgr.IsShadow() {
		mgr.SetShadowCleanup(func(ip netip.Addr) error {
			if err := hostnet.CleanupConntrack(ip); err != nil {
				log.Printf("conntrack cleanup failed: %v", err)
				return err
			}
			return nil
		})
	}
	packetPool := session.NewPacketPool(c.Server.MTU)
	fatal := make(chan error, 2)
	go tunDispatcher(tun, mgr, packetPool, fatal)
	qc := &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 32}
	transport := &quic.Transport{Conn: packetConn, StatelessResetKey: &resetKey}
	ql, err := transport.Listen(http3.ConfigureTLSConfig(tc), qc)
	if err != nil {
		return err
	}
	defer ql.Close()
	defer transport.Close()
	externalInterface := c.HostNetwork.ExternalInterface
	if externalInterface == "" {
		externalInterface, err = hostnet.DefaultExternalInterface()
		if err != nil {
			return fmt.Errorf("detect external interface: %w", err)
		}
	}
	checkInterval, _ := time.ParseDuration(c.HostNetwork.CheckInterval)
	probe := hostnet.Probe{
		TunnelName: "masque0", TunnelPrefix: serverPrefix, TunnelMTU: c.Server.MTU,
		ExternalInterface: externalInterface,
		TunnelCheck:       tunnel.CheckInterface,
		ForwardingCheck:   hostnet.CheckIPv4Forwarding,
		NATCheck:          hostnet.CheckNAT,
	}
	if err := probe.Check(); err != nil {
		return fmt.Errorf("data-plane unhealthy: %w", err)
	}
	s := &http3.Server{TLSConfig: tc, QUICConfig: qc, EnableDatagrams: true, Handler: mh.HandlerFunc(func(w mh.ResponseWriter, r *mh.Request) { handleRequest(w, r, c, byKey, mgr, tun, packetPool) })}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.ServeListener(ql) }()
	appCtx, stopReaper := context.WithCancel(context.Background())
	defer stopReaper()
	idleTimeout, _ := time.ParseDuration(c.Server.SessionIdleTimeout)
	if idleTimeout > 0 {
		go sessionReaper(appCtx, mgr, idleTimeout)
	}
	supervisor := hostnet.Supervisor{Probe: probe, Interval: checkInterval}
	go supervisor.Run(appCtx, fatal, func() { _ = notify.Send("WATCHDOG=1") })
	if err := notify.Send("READY=1"); err != nil {
		log.Printf("systemd notify failed: %v", err)
	}
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
	stopReaper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = s.Shutdown(ctx); err != nil {
		_ = s.Close()
	}
	return runErr
}

func isServerClosed(err error) bool {
	return errors.Is(err, stdhttp.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

func sessionReaper(ctx context.Context, mgr *session.Manager, timeout time.Duration) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			reapIdle(mgr, now, timeout)
		}
	}
}

func reapIdle(mgr *session.Manager, now time.Time, timeout time.Duration) int {
	if timeout <= 0 {
		return 0
	}
	closed := 0
	for _, s := range mgr.Snapshot() {
		if now.Sub(s.LastActivity()) < timeout {
			continue
		}
		if now.Sub(s.LastActivity()) >= timeout {
			s.SetCloseReason("idle-timeout")
			s.Close()
			closed++
		}
	}
	return closed
}

func handleRequest(w mh.ResponseWriter, r *mh.Request, c config.Config, byKey map[string]config.ResolvedClient, mgr *session.Manager, tun *tunnel.Device, packetPool *session.PacketPool) {
	serverPrefix, _ := netip.ParsePrefix(c.Server.TunnelIPv4)
	parseProtocol, ok := protocolForParse(r.Proto)
	if !ok {
		log.Printf("CONNECT-IP rejected: unsupported protocol %q", r.Proto)
		mh.Error(w, "only CONNECT-IP is supported", mh.StatusNotImplemented)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		log.Printf("CONNECT-IP rejected: missing client certificate")
		mh.Error(w, "client certificate required", mh.StatusUnauthorized)
		return
	}
	client, ok := byKey[auth.PublicKeyBytes(r.TLS.PeerCertificates[0])]
	if !ok {
		log.Printf("CONNECT-IP rejected: unauthorized client")
		mh.Error(w, "client certificate not authorized", mh.StatusUnauthorized)
		return
	}
	release, err := mgr.TryReserveFor(client.Name)
	if err != nil {
		log.Printf("CONNECT-IP rejected: session admission: %v", err)
		mh.Error(w, "session capacity unavailable", mh.StatusServiceUnavailable)
		return
	}
	defer release()
	template, err := requestTemplate(r.Host)
	if err != nil {
		log.Printf("CONNECT-IP rejected: invalid authority: %v", err)
		mh.Error(w, "invalid authority", mh.StatusBadRequest)
		return
	}
	copyReq := *r
	copyReq.Proto = parseProtocol
	req, err := connectip.ParseRequest(&copyReq, template)
	if err != nil {
		log.Printf("CONNECT-IP request parse failed: %v", err)
		mh.Error(w, err.Error(), mh.StatusBadRequest)
		return
	}
	conn, err := (&connectip.Proxy{}).Proxy(w, req)
	if err != nil {
		log.Printf("CONNECT-IP tunnel establishment failed: %v", err)
		return
	}
	if err = conn.AssignAddresses(r.Context(), []netip.Prefix{client.TunnelIPv4}); err != nil {
		log.Printf("AssignAddresses failed: %v", err)
		conn.Close()
		return
	}
	if err = conn.AdvertiseRoute(r.Context(), []connectip.IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}}); err != nil {
		log.Printf("AdvertiseRoute failed: %v", err)
		conn.Close()
		return
	}
	s := session.NewWithContextAndPacketPoolAndQueue(r.Context(), client.TunnelIPv4.Addr(), client.Name, conn, packetPool, c.Server.OutboundQueueSize, func(x *session.Session) { mgr.RemoveIfCurrent(x) })
	if mgr.IsShadow() {
		if err := mgr.Register(s); err != nil {
			log.Printf("session registration failed: %v", err)
			s.Close()
			mh.Error(w, "session capacity unavailable", mh.StatusServiceUnavailable)
			return
		}
	} else {
		old := mgr.Replace(s)
		if old != nil {
			log.Printf("session takeover")
		}
	}
	release()
	go sessionWriter(s, tun, c.Server.MTU)
	log.Printf("session=%d established", s.ID)
	go sessionReader(s, tun, mgr, serverPrefix, c.DNSGateway.IsEnabled(), uint16(c.DNSGateway.Port))
	select {
	case <-r.Context().Done():
	case <-s.Ctx.Done():
	}
	s.Close()
	reason := s.CloseReason()
	if reason == "" {
		reason = "peer"
	}
	if r.Context().Err() != nil {
		reason = "context"
	}
	log.Printf("session=%d closed reason=%s", s.ID, reason)
}

func tunDispatcher(tun *tunnel.Device, mgr *session.Manager, packetPool *session.PacketPool, fatal chan<- error) {
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			fatal <- fmt.Errorf("TUN dispatcher: %w", err)
			return
		}
		dst, ok := packet.Destination(buf[:n])
		if !ok {
			continue
		}
		s := mgr.Lookup(dst)
		if s == nil {
			continue
		}
		pkt := packetPool.Get(n)
		copy(pkt.Data, buf[:n])
		if mgr.IsShadow() {
			if pkt.Data[9] == 1 {
				if !packet.TranslateICMP(pkt.Data, s.VisibleIP, s.ShadowIP, false) {
					packetPool.Put(pkt)
					continue
				}
			} else if !packet.RewriteDestinationIPv4(pkt.Data, s.ShadowIP, s.VisibleIP) {
				packetPool.Put(pkt)
				continue
			}
		}
		if !s.TryEnqueue(pkt) {
			mgr.RecordQueueOverflow()
			now := time.Now().Unix()
			previous := lastQueueOverflowLog.Load()
			if now-previous >= 30 && lastQueueOverflowLog.CompareAndSwap(previous, now) {
				log.Printf("CONNECT-IP outbound queue overflow: aggregate_drops=%d", mgr.QueueOverflowTotal())
			}
		}
	}
}
func sessionWriter(s *session.Session, tun *tunnel.Device, mtu int) {
	for {
		select {
		case <-s.Ctx.Done():
			return
		case pkt := <-s.Outbound:
			s.RecordDequeued()
			var icmp []byte
			var err error
			if fast, ok := s.Conn.(interface {
				WritePacketBuffer([]byte, int, int) ([]byte, error)
			}); ok {
				icmp, err = fast.WritePacketBuffer(pkt.Buffer, 1, len(pkt.Data))
			} else {
				icmp, err = s.Conn.WritePacket(pkt.Data)
			}
			s.ReleasePacket(pkt)
			if len(icmp) > 0 {
				if s.ShadowIP.IsValid() && s.ShadowIP != s.VisibleIP && !packet.TranslateICMP(icmp, s.VisibleIP, s.ShadowIP, true) {
					continue
				}
				if _, werr := tun.Write(icmp); werr != nil {
					s.SetCloseReason("tun-write-error")
					log.Printf("session=%d ICMP write failed: %v", s.ID, werr)
					s.Close()
					return
				}
			}
			if err != nil {
				if normalSessionError(err, s.Ctx) {
					return
				}
				s.SetCloseReason("write-error")
				log.Printf("session=%d packet write failed: %v", s.ID, err)
				s.Close()
				return
			}
			s.Touch(time.Now())
		}
	}
}
func sessionReader(s *session.Session, tun *tunnel.Device, mgr *session.Manager, serverPrefix netip.Prefix, dnsEnabled bool, dnsPort uint16) {
	for {
		pkt, err := s.Conn.ReadPacket()
		if err != nil {
			if normalSessionError(err, s.Ctx) {
				return
			}
			s.SetCloseReason("read-error")
			log.Printf("session=%d session read failed: %v", s.ID, err)
			s.Close()
			return
		}
		src, ok := packet.Source(pkt)
		if !ok || src != s.VisibleIP {
			continue
		}
		dst, ok := packet.Destination(pkt)
		isDNS := dnsEnabled && dst == serverPrefix.Addr() && packet.IsTCPOrUDPDestinationPort(pkt, dnsPort)
		if !ok || (!isDNS && serverPrefix.Contains(dst)) || mgr.IsShadowAddress(dst) {
			continue
		}
		select {
		case <-s.Ctx.Done():
			return
		default:
		}
		if s.ShadowIP.IsValid() && s.ShadowIP != s.VisibleIP {
			if pkt[9] == 1 {
				if !packet.TranslateICMP(pkt, s.VisibleIP, s.ShadowIP, true) {
					continue
				}
			} else if !packet.RewriteSourceIPv4(pkt, s.VisibleIP, s.ShadowIP) {
				continue
			}
		}
		if _, err = tun.Write(pkt); err != nil {
			s.SetCloseReason("tun-write-error")
			log.Printf("session=%d TUN write failed: %v", s.ID, err)
			s.Close()
			return
		}
		s.Touch(time.Now())
	}
}
func protocolForParse(protocol string) (string, bool) {
	switch protocol {
	case "connect-ip", "cf-connect-ip":
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
	return ctx.Err() != nil || err == context.Canceled || err == net.ErrClosed || err == io.ErrClosedPipe
}
