package main

import (
	"context"
	"crypto/tls"
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
	"sync/atomic"
	"syscall"
	"time"

	connectip "github.com/Piggy-Cat-bit-shadow/connect-ip-go"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/auth"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/dnsgateway"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/hostnet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/packet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/quicstate"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/session"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/tunnel"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/notify"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
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
	if err := validateQLogDirectory(c.Diagnostics.QLog); err != nil {
		return err
	}
	serverAddresses, err := c.ServerAddresses()
	if err != nil {
		return err
	}
	if err := hostnet.CheckForwarding(serverAddresses.Prefixes()); err != nil {
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
	tun, err := tunnel.Open("masque0", c.Server.MTU, c.Server.TunOffload, c.Server.TunTXGRO)
	if err != nil {
		return err
	}
	defer tun.Close()
	if tun.OffloadEnabled() {
		log.Printf("CONNECT-IP TUN mode: vnet-hdr-gso")
	} else {
		log.Printf("CONNECT-IP TUN mode: plain")
	}
	if err = tun.ConfigureAddresses(serverAddresses.Prefixes()); err != nil {
		return fmt.Errorf("configure masque0: %w", err)
	}
	var dnsGateway *dnsgateway.Gateway
	if c.DNSGateway.IsEnabled() {
		dnsTimeout, _ := time.ParseDuration(c.DNSGateway.Timeout)
		dnsGateway, err = dnsgateway.StartMany(dnsgateway.Config{
			ListenAddr: serverAddresses.IPv4.Addr(), Port: c.DNSGateway.Port, Upstream: c.DNSGateway.Upstream,
			Timeout: dnsTimeout, Concurrency: c.DNSGateway.Concurrency,
		}, serverAddresses.Addresses())
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
	if buffers, berr := readSocketBufferSizes(packetConn); berr != nil {
		log.Printf("CONNECT-IP UDP socket buffers unavailable: %v", berr)
	} else {
		log.Printf("CONNECT-IP UDP socket buffers: rcv=%d send=%d bytes (effective; requested quic-go target is 7340032)", buffers.Receive, buffers.Send)
	}
	var mgr *session.Manager
	if c.Server.SessionNat.Enabled {
		pool, _ := netip.ParsePrefix(c.Server.SessionNat.Pool)
		excluded := make([]netip.Addr, 0, len(clients)+1)
		excluded = append(excluded, serverAddresses.IPv4.Addr())
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
		defer mgr.CloseCleanup()
	}
	packetPool := session.NewPacketPool(c.Server.MTU)
	fatal := make(chan error, 2)
	go tunDispatcher(tun, mgr, packetPool, fatal)
	qc := &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 32, Tracer: newQLogTracer(c.Diagnostics.QLog)}
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
		TunnelName: "masque0", TunnelPrefix: firstPrefix(serverAddresses), TunnelPrefixes: serverAddresses.Prefixes(), TunnelMTU: c.Server.MTU,
		ExternalInterface: externalInterface,
		TunnelCheck:       tunnel.CheckInterface,
		ForwardingCheck:   func() error { return hostnet.CheckForwarding(serverAddresses.Prefixes()) },
		NATCheck:          hostnet.CheckNAT,
	}
	if err := probe.Check(); err != nil {
		return fmt.Errorf("data-plane unhealthy: %w", err)
	}
	log.Printf("CONNECT-IP QUIC congestion controller: %s", c.QUIC.CongestionController)
	s := &http3.Server{TLSConfig: tc, QUICConfig: qc, EnableDatagrams: true, ConnContext: connectIPConnContext(c.QUIC.CongestionController), Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		handleRequest(w, r, c, serverAddresses, byKey, mgr, tun, packetPool)
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.ServeListener(ql) }()
	appCtx, stopReaper := context.WithCancel(context.Background())
	defer stopReaper()
	go connectIPDiagnostics(appCtx, mgr, tun)
	idleTimeout, _ := time.ParseDuration(c.Server.SessionIdleTimeout)
	if idleTimeout > 0 {
		go sessionReaper(appCtx, mgr, idleTimeout)
	}
	supervisor := hostnet.Supervisor{Probe: probe, Interval: checkInterval}
	go supervisor.Run(appCtx, fatal)
	if err := notify.Send("READY=1"); err != nil {
		log.Printf("systemd notify failed: %v", err)
	}
	go runSystemdWatchdog(appCtx)
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

// connectIPDiagnostics emits identity-free, rate-limited dataplane counters.
// It is intentionally a periodic snapshot: packet-level logging would itself
// distort the WAN path being diagnosed.
func connectIPDiagnostics(ctx context.Context, mgr *session.Manager, tun *tunnel.Device) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q := mgr.AggregateQueueStats()
			qs := mgr.AggregateRuntimeStats()
			t := tun.Stats()
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			log.Printf("CONNECT-IP dataplane: sessions=%d queue_depth=%d/%d queue_high=%d enqueued=%d dequeued=%d dropped=%d tun_rx=%d/%dB tun_tx=%d/%dB tun_rx_batches=%d packets=%d quic_connections=%d cwnd=%dB in_flight=%dB pacing=%dBps rtt_min=%s rtt_latest=%s rtt_smoothed=%s lost=%d/%dB spurious=%d reorder=%d/%s datagram_queue=%d/%d blocked=%d/%s send_queue=%d/%d hard_block=%d/%s rx_queue_drops=%d/%d pmtu=%d gso=%d heap=%dB gc=%d", q.Sessions, q.Depth, q.Capacity, q.HighWater, q.Enqueued, q.Dequeued, q.Dropped, t.RXPackets, t.RXBytes, t.TXPackets, t.TXBytes, t.RXBatches, t.RXBatchPackets, qs.Connections, qs.CongestionWindows, qs.BytesInFlight, qs.PacingRate, qs.MinRTT, qs.LatestRTT, qs.SmoothedRTT, qs.PacketsLost, qs.BytesLost, qs.SpuriousLosses, qs.MaxPacketReordering, qs.MaxTimeReordering, qs.DatagramQueueDepth, qs.DatagramQueueHighWater, qs.DatagramBlocked, qs.DatagramBlockedDuration, qs.SendQueueDepth, qs.SendQueueHighWater, qs.SendQueueHardBlocks, qs.SendQueueHardBlockedDuration, qs.ReceivedPacketQueueDrops, qs.ReceivedDatagramQueueDrops, qs.CurrentPMTU, qs.GSOConnections, mem.HeapAlloc, mem.NumGC)
		}
	}
}

func isServerClosed(err error) bool {
	return errors.Is(err, stdhttp.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

// runSystemdWatchdog is deliberately independent of host-network probing. It
// only proves that this service's runtime can schedule and send a heartbeat;
// it does not claim that QUIC or the packet datapath is making progress.
func runSystemdWatchdog(ctx context.Context) {
	interval, ok := notify.WatchdogInterval()
	if !ok {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := notify.Send("WATCHDOG=1"); err != nil {
				if !warned {
					log.Printf("systemd watchdog notify failed: %v", err)
					warned = true
				}
				continue
			}
			warned = false
		}
	}
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

func handleRequest(w stdhttp.ResponseWriter, r *stdhttp.Request, c config.Config, serverAddresses config.TunnelAddresses, byKey map[string]config.ResolvedClient, mgr *session.Manager, tun *tunnel.Device, packetPool *session.PacketPool) {
	parseProtocol, ok := protocolForParse(r.Proto)
	if !ok {
		log.Printf("CONNECT-IP rejected: unsupported protocol %q", r.Proto)
		stdhttp.Error(w, "only CONNECT-IP is supported", stdhttp.StatusNotImplemented)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		log.Printf("CONNECT-IP rejected: missing client certificate")
		stdhttp.Error(w, "client certificate required", stdhttp.StatusUnauthorized)
		return
	}
	client, ok := byKey[auth.PublicKeyBytes(r.TLS.PeerCertificates[0])]
	if !ok {
		log.Printf("CONNECT-IP rejected: unauthorized client")
		stdhttp.Error(w, "client certificate not authorized", stdhttp.StatusUnauthorized)
		return
	}
	release, err := mgr.TryReserveFor(client.Name)
	if err != nil {
		log.Printf("CONNECT-IP rejected: session admission: %v", err)
		stdhttp.Error(w, "session capacity unavailable", stdhttp.StatusServiceUnavailable)
		return
	}
	defer release()
	template, err := requestTemplate(r.Host)
	if err != nil {
		log.Printf("CONNECT-IP rejected: invalid authority: %v", err)
		stdhttp.Error(w, "invalid authority", stdhttp.StatusBadRequest)
		return
	}
	copyReq := r.Clone(r.Context())
	copyReq.Proto = parseProtocol
	req, err := connectip.ParseProxyRequest(copyReq, template)
	if err != nil {
		log.Printf("CONNECT-IP request parse failed: %v", err)
		stdhttp.Error(w, err.Error(), stdhttp.StatusBadRequest)
		return
	}
	conn, err := (&connectip.Proxy{}).Proxy(w, req)
	if err != nil {
		log.Printf("CONNECT-IP tunnel establishment failed: %v", err)
		return
	}
	clientAddresses := config.TunnelAddresses{IPv4: client.TunnelIPv4, IPv6: client.TunnelIPv6}
	if err = conn.AssignAddresses(clientAddresses.Prefixes()); err != nil {
		log.Printf("AssignAddresses failed: %v", err)
		conn.Close()
		return
	}
	if err = conn.AdvertiseRoute(fullTunnelRoutes(clientAddresses, c.Server.AdvertiseIPv6DefaultRoute)); err != nil {
		log.Printf("AdvertiseRoute failed: %v", err)
		conn.Close()
		return
	}
	s := session.NewWithAddressesAndPacketPoolAndQueue(r.Context(), clientAddresses.Addresses(), client.Name, legacyPacketConn{conn}, packetPool, c.Server.OutboundQueueSize, func(x *session.Session) { mgr.RemoveIfCurrent(x) })
	if mgr.IsShadow() {
		if err := mgr.Register(s); err != nil {
			log.Printf("session registration failed: %v", err)
			s.Close()
			stdhttp.Error(w, "session capacity unavailable", stdhttp.StatusServiceUnavailable)
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
	go sessionReaderWithAddresses(s, tun, mgr, serverAddresses, c.DNSGateway.IsEnabled(), uint16(c.DNSGateway.Port))
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

func firstPrefix(a config.TunnelAddresses) netip.Prefix {
	if a.IPv4.IsValid() {
		return a.IPv4
	}
	return a.IPv6
}
func fullTunnelRoutes(a config.TunnelAddresses, advertiseIPv6DefaultRoute bool) []connectip.IPRoute {
	routes := make([]connectip.IPRoute, 0, 2)
	if a.IPv4.IsValid() {
		routes = append(routes, connectip.IPRoute{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")})
	}
	if a.IPv6.IsValid() && advertiseIPv6DefaultRoute {
		routes = append(routes, connectip.IPRoute{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")})
	}
	return routes
}

func txGRODrainEnabled(tunTXGRO, canTryOwned, canTryLegacy bool) bool {
	return tunTXGRO && (canTryOwned || canTryLegacy)
}

// sessionDrainEnabled is independent of TX GRO. A connected-IP stream can
// expose a nonblocking receive API even when TUN offload is disabled; draining
// a bounded ready burst still amortizes stream/channel wakeups, while
// WriteBatch safely falls back to individual TUN writes on the plain path.
func sessionDrainEnabled(canTryOwned, canTryLegacy bool) bool {
	return canTryOwned || canTryLegacy
}

// legacyPacketConn adapts the v0.62 connect-ip-go ReadPacket buffer API to
// the session layer's established packet-ownership contract.
type legacyPacketConn struct{ *connectip.Conn }

func (c legacyPacketConn) RuntimeStats() quic.RuntimeStats { return c.Conn.RuntimeStats() }

func (c legacyPacketConn) ReadPacket() ([]byte, error) {
	buf := make([]byte, 64*1024)
	n, err := c.Conn.ReadPacket(buf)
	return buf[:n], err
}

type tunPacketReader interface {
	Read([]byte) (int, error)
}

func tunDispatcher(tun *tunnel.Device, mgr *session.Manager, packetPool *session.PacketPool, fatal chan<- error) {
	if tun.OffloadEnabled() {
		tunDispatcherBatchLoop(tun, mgr, packetPool, fatal)
		return
	}
	tunDispatcherReadLoop(tun, mgr, packetPool, fatal)
}

func dispatchTUNPacket(pkt *session.PacketBuffer, mgr *session.Manager, packetPool *session.PacketPool) bool {
	dst, ok := packet.Destination(pkt.Data)
	if !ok {
		packetPool.Put(pkt)
		return false
	}
	s := mgr.Lookup(dst)
	if s == nil {
		packetPool.Put(pkt)
		return false
	}
	if mgr.IsShadow() {
		if pkt.Data[9] == 1 {
			if !packet.TranslateICMP(pkt.Data, s.VisibleIP, s.ShadowIP, false) {
				packetPool.Put(pkt)
				return false
			}
		} else if !packet.RewriteDestinationIPv4(pkt.Data, s.ShadowIP, s.VisibleIP) {
			packetPool.Put(pkt)
			return false
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
	return true
}

func tunDispatcherBatchLoop(tun *tunnel.Device, mgr *session.Manager, packetPool *session.PacketPool, fatal chan<- error) {
	packets := make([]*session.PacketBuffer, tunnel.MaxGSOBatch)
	bufs := make([][]byte, tunnel.MaxGSOBatch)
	sizes := make([]int, tunnel.MaxGSOBatch)
	for {
		fillTUNBatchSlots(packets, bufs, sizes, packetPool)
		n, err := tun.ReadBatch(bufs, sizes, session.PacketPoolHeadroom)
		if err != nil {
			releaseTUNBatchSlots(packets, packetPool)
			if errors.Is(err, tunnel.ErrMalformedGSO) {
				continue
			}
			fatal <- fmt.Errorf("TUN dispatcher: %w", err)
			return
		}
		for i, pkt := range packets {
			if i >= n {
				continue
			}
			if !packetPool.CommitRead(pkt, sizes[i]) {
				packetPool.Put(pkt)
				packets[i] = nil
				continue
			}
			packets[i] = nil // dispatchTUNPacket transfers or releases ownership.
			dispatchTUNPacket(pkt, mgr, packetPool)
		}
	}
}

// fillTUNBatchSlots only replaces buffers whose ownership left the dispatcher
// in the preceding iteration. A normal VNET_HDR record produces one packet,
// so retaining the remaining slots avoids pool churn while preserving room for
// a maximum-size GSO split on the next read.
func fillTUNBatchSlots(packets []*session.PacketBuffer, bufs [][]byte, sizes []int, packetPool *session.PacketPool) {
	for i := range packets {
		if packets[i] == nil {
			packets[i] = packetPool.Get(packetPool.PayloadSize())
		}
		bufs[i] = packets[i].Buffer
		sizes[i] = 0
	}
}

func releaseTUNBatchSlots(packets []*session.PacketBuffer, packetPool *session.PacketPool) {
	for i, pkt := range packets {
		if pkt != nil {
			packetPool.Put(pkt)
			packets[i] = nil
		}
	}
}

func tunDispatcherReadLoop(tun tunPacketReader, mgr *session.Manager, packetPool *session.PacketPool, fatal chan<- error) {
	for {
		pkt := packetPool.AcquireForRead()
		n, err := tun.Read(pkt.Data)
		if err != nil {
			packetPool.Put(pkt)
			fatal <- fmt.Errorf("TUN dispatcher: %w", err)
			return
		}
		if !packetPool.CommitRead(pkt, n) {
			packetPool.Put(pkt)
			continue
		}
		dispatchTUNPacket(pkt, mgr, packetPool)
	}
}

const sessionWriterDrainMax = 32

type packetBufferOwnedWriter interface {
	WritePacketBufferOwned([]byte, int, int, connectip.PacketPayloadOwner) ([]byte, error)
}

type packetBufferWriter interface {
	WritePacketBuffer([]byte, int, int) ([]byte, error)
}

type sessionPacketWriter struct {
	conn   session.PacketConn
	owned  packetBufferOwnedWriter
	buffer packetBufferWriter
}

func newSessionPacketWriter(conn session.PacketConn) sessionPacketWriter {
	w := sessionPacketWriter{conn: conn}
	w.owned, _ = conn.(packetBufferOwnedWriter)
	if w.owned == nil {
		w.buffer, _ = conn.(packetBufferWriter)
	}
	return w
}

// write sends one packet and follows the owned-send contract: a nil error
// transfers ownership; an error leaves it with this writer. connect-ip-go
// already releases synchronous rejected paths, and PacketBuffer.Release is
// deliberately idempotent, so releasing here also makes the generic optional
// interface safe for implementations that leave rejected ownership to us.
func (w sessionPacketWriter) write(s *session.Session, pkt *session.PacketBuffer) ([]byte, error) {
	if w.owned != nil {
		icmp, err := w.owned.WritePacketBufferOwned(pkt.Buffer, session.PacketPoolHeadroom, len(pkt.Data), pkt)
		if err != nil {
			s.ReleasePacket(pkt)
		}
		return icmp, err
	}
	if w.buffer != nil {
		icmp, err := w.buffer.WritePacketBuffer(pkt.Buffer, session.PacketPoolHeadroom, len(pkt.Data))
		s.ReleasePacket(pkt)
		return icmp, err
	}
	icmp, err := w.conn.WritePacket(pkt.Data)
	s.ReleasePacket(pkt)
	return icmp, err
}

type tunPacketWriter interface {
	Write([]byte) (int, error)
}

func releaseSessionPackets(s *session.Session, packets []*session.PacketBuffer) {
	for _, pkt := range packets {
		s.ReleasePacket(pkt)
	}
}

// drainSessionWriterReady appends only packets already queued at the time of
// the drain. It never waits for future work, keeps FIFO order, and keeps the
// locally owned burst small enough that cancellation cleanup is bounded.
func drainSessionWriterReady(first *session.PacketBuffer, outbound <-chan *session.PacketBuffer, batch []*session.PacketBuffer) []*session.PacketBuffer {
	batch = append(batch[:0], first)
	for len(batch) < sessionWriterDrainMax {
		select {
		case pkt := <-outbound:
			batch = append(batch, pkt)
		default:
			return batch
		}
	}
	return batch
}

func sessionWriter(s *session.Session, tun *tunnel.Device, mtu int) {
	sessionWriterWithTUNWriter(s, tun, mtu)
}

func sessionWriterWithTUNWriter(s *session.Session, tun tunPacketWriter, mtu int) {
	writer := newSessionPacketWriter(s.Conn)
	batch := make([]*session.PacketBuffer, 0, sessionWriterDrainMax)
	for {
		select {
		case <-s.Ctx.Done():
			return
		case pkt := <-s.Outbound:
			batch = drainSessionWriterReady(pkt, s.Outbound, batch)
		}
		s.RecordDequeuedN(len(batch))
		successful := 0
		for i, pkt := range batch {
			if s.Ctx.Err() != nil {
				if successful > 0 {
					s.Touch(time.Now())
				}
				releaseSessionPackets(s, batch[i:])
				return
			}
			icmp, err := writer.write(s, pkt)
			if len(icmp) > 0 {
				if s.ShadowIP.IsValid() && s.ShadowIP != s.VisibleIP && !packet.TranslateICMP(icmp, s.VisibleIP, s.ShadowIP, true) {
					// Do not let an untranslated response skip error handling for
					// this packet or disrupt the rest of the burst.
				} else if _, werr := tun.Write(icmp); werr != nil {
					if successful > 0 {
						s.Touch(time.Now())
					}
					releaseSessionPackets(s, batch[i+1:])
					s.SetCloseReason("tun-write-error")
					log.Printf("session=%d ICMP write failed: %v", s.ID, werr)
					s.Close()
					return
				}
			}
			if err != nil {
				if successful > 0 {
					s.Touch(time.Now())
				}
				releaseSessionPackets(s, batch[i+1:])
				if normalSessionError(err, s.Ctx) {
					return
				}
				s.SetCloseReason("write-error")
				log.Printf("session=%d packet write failed: %v", s.ID, err)
				s.Close()
				return
			}
			successful++
		}
		// A drained burst is already-ready work. Its tail timestamp is the
		// most recent successful activity and avoids a clock read per packet.
		s.Touch(time.Now())
	}
}
func sessionReader(s *session.Session, tun *tunnel.Device, mgr *session.Manager, serverPrefix netip.Prefix, dnsEnabled bool, dnsPort uint16) {
	serverReaderAddresses := tunnelAddressesFromArg(serverPrefix)
	sessionReaderWithAddresses(s, tun, mgr, serverReaderAddresses, dnsEnabled, dnsPort)
}

func sessionReaderWithAddresses(s *session.Session, tun *tunnel.Device, mgr *session.Manager, serverAddresses config.TunnelAddresses, dnsEnabled bool, dnsPort uint16) {
	tryReader, canTry := s.Conn.(interface{ TryReadPacket() ([]byte, error) })
	ownedReader, canReadOwned := s.Conn.(interface {
		ReadPacketBuffer() (*connectip.PacketBuffer, error)
	})
	ownedTryReader, canTryOwned := s.Conn.(interface {
		TryReadPacketBuffer() (*connectip.PacketBuffer, error)
	})
	for {
		var pkt []byte
		var release func()
		var err error
		if canReadOwned {
			var owned *connectip.PacketBuffer
			owned, err = ownedReader.ReadPacketBuffer()
			if err == nil {
				pkt, release = owned.Data, owned.Release
			}
		} else {
			pkt, err = s.Conn.ReadPacket()
			release = func() {}
		}
		if err != nil {
			if normalSessionError(err, s.Ctx) {
				return
			}
			s.SetCloseReason("read-error")
			log.Printf("session=%d session read failed: %v", s.ID, err)
			s.Close()
			return
		}
		if !prepareSessionPacket(pkt, s, mgr, serverAddresses, dnsEnabled, dnsPort) {
			release()
			continue
		}
		batch := [][]byte{pkt}
		releases := []func(){release}
		if sessionDrainEnabled(canTryOwned, canTry) {
			for len(batch) < tunnel.MaxTXGROBatch {
				var next []byte
				var nextRelease func()
				var pollErr error
				if canTryOwned {
					var owned *connectip.PacketBuffer
					owned, pollErr = ownedTryReader.TryReadPacketBuffer()
					if pollErr == nil {
						next, nextRelease = owned.Data, owned.Release
					}
				} else {
					next, pollErr = tryReader.TryReadPacket()
					nextRelease = func() {}
				}
				if errors.Is(pollErr, context.Canceled) {
					break
				}
				if pollErr != nil {
					err = pollErr
					break
				}
				if prepareSessionPacket(next, s, mgr, serverAddresses, dnsEnabled, dnsPort) {
					batch = append(batch, next)
					releases = append(releases, nextRelease)
				} else {
					nextRelease()
				}
			}
		}
		if err == nil {
			if len(batch) == 1 {
				_, err = tun.Write(batch[0])
			} else {
				_, err = tun.WriteBatch(batch)
			}
		}
		if err != nil {
			for _, done := range releases {
				done()
			}
			s.SetCloseReason("tun-write-error")
			log.Printf("session=%d TUN write failed: %v", s.ID, err)
			s.Close()
			return
		}
		for _, done := range releases {
			done()
		}
		s.Touch(time.Now())
	}
}

func tunnelAddressesFromArg(arg any) config.TunnelAddresses {
	switch value := arg.(type) {
	case config.TunnelAddresses:
		return value
	case netip.Prefix:
		if value.Addr().Is4() {
			return config.TunnelAddresses{IPv4: value}
		}
		return config.TunnelAddresses{IPv6: value}
	default:
		return config.TunnelAddresses{}
	}
}

func prepareSessionPacket(pkt []byte, s *session.Session, mgr *session.Manager, serverAddresses config.TunnelAddresses, dnsEnabled bool, dnsPort uint16) bool {
	info, ok := packet.Parse(pkt)
	if !ok || !s.OwnsAddress(info.Source) {
		return false
	}
	dst := info.Destination
	isDNS := dnsEnabled && containsAddress(serverAddresses, dst) && packet.IsTCPOrUDPDestinationPort(pkt, dnsPort)
	if !ok || (!isDNS && containsPrefix(serverAddresses, dst)) || mgr.IsShadowAddress(dst) {
		return false
	}
	select {
	case <-s.Ctx.Done():
		return false
	default:
	}
	if s.ShadowIP.IsValid() && s.ShadowIP != s.VisibleIP {
		if len(pkt) < 10 {
			return false
		}
		if pkt[9] == 1 {
			if !packet.TranslateICMP(pkt, s.VisibleIP, s.ShadowIP, true) {
				return false
			}
		} else if !packet.RewriteSourceIPv4(pkt, s.VisibleIP, s.ShadowIP) {
			return false
		}
	}
	return true
}

func containsPrefix(a config.TunnelAddresses, ip netip.Addr) bool {
	return (a.IPv4.IsValid() && a.IPv4.Contains(ip)) || (a.IPv6.IsValid() && a.IPv6.Contains(ip))
}
func containsAddress(a config.TunnelAddresses, ip netip.Addr) bool {
	return (a.IPv4.IsValid() && a.IPv4.Addr() == ip) || (a.IPv6.IsValid() && a.IPv6.Addr() == ip)
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
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
