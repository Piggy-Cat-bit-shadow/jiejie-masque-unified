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
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/diagnostics"
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
var connectIPPipeline atomic.Pointer[diagnostics.Probe]
var datagramWriterTelemetry struct {
	tryCalls atomic.Uint64
	partial  atomic.Uint64
	zero     atomic.Uint64
	waits    atomic.Uint64
	waitNS   atomic.Uint64
	canceled atomic.Uint64
}

func runConnectIPLegacy() {
	if err := serveConnectIP(); err != nil {
		log.Fatal(err)
	}
}

func serveConnectIP() error {
	return serveConnectIPArgs(os.Args[1:])
}

func serveConnectIPArgs(args []string) error {
	if len(args) > 0 && args[0] == "diagnose-report" {
		if len(args) != 2 {
			return fmt.Errorf("usage: diagnose-report FILE")
		}
		return diagnoseReport(args[1])
	}
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
	connectIPPipeline.Store(nil)
	if c.Diagnostics.Pipeline.Enabled {
		connectIPPipeline.Store(&diagnostics.Probe{})
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
	var preSocketBuffers socketBufferSizes
	if buffers, berr := readSocketBufferSizes(packetConn); berr != nil {
		log.Printf("CONNECT-IP UDP socket buffers unavailable: %v", berr)
	} else {
		preSocketBuffers = buffers
		log.Printf("CONNECT-IP UDP socket buffers before quic-go tuning: rcv=%d send=%d bytes", buffers.Receive, buffers.Send)
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
	if postSocketBuffers, berr := readSocketBufferSizes(packetConn); berr != nil {
		log.Printf("CONNECT-IP UDP socket buffers after quic-go tuning unavailable: %v", berr)
	} else {
		log.Printf("%s", formatSocketBufferLog(preSocketBuffers, postSocketBuffers, 7340032))
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
	go connectIPDiagnostics(appCtx, mgr, tun, c.Diagnostics.Pipeline)
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
func connectIPDiagnostics(ctx context.Context, mgr *session.Manager, tun *tunnel.Device, cfg config.Pipeline) {
	interval := 30 * time.Second
	if cfg.Enabled {
		interval, _ = time.ParseDuration(cfg.Interval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var previous map[diagnostics.Stage]diagnostics.Point
	var previousAt time.Time
	var previousRuntime session.AggregateRuntimeStats
	var previousTun tunnel.Stats
	var previousWriterWaitNS uint64
	intervalAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			intervalNow := time.Now()
			intervalElapsed := intervalNow.Sub(intervalAt)
			intervalAt = intervalNow
			if probe := connectIPPipeline.Load(); cfg.Enabled && probe != nil {
				now := time.Now()
				baseline := previousAt.IsZero()
				elapsed := interval
				if !baseline {
					elapsed = now.Sub(previousAt)
				}
				snapshot, next := probe.Snapshot(previous, elapsed)
				snapshot.Timestamp = now.UTC().Format(time.RFC3339Nano)
				previous, previousAt = next, now
				runtimeStats := mgr.AggregateRuntimeStats()
				intervalSegmentBuckets := counterBucketDelta(runtimeStats.SegmentsPerWriteBuckets, previousRuntime.SegmentsPerWriteBuckets)
				packetSizeDelta := counterBucketDelta8(runtimeStats.PackedPacketSizeBuckets, previousRuntime.PackedPacketSizeBuckets)
				if baseline {
					intervalSegmentBuckets = [65]uint64{}
					packetSizeDelta = [8]uint64{}
				}
				setRuntimeStage(&snapshot, diagnostics.QUICDatagramEnqueue, runtimeStats.DatagramEnqueueBytes, runtimeStats.DatagramEnqueue, counterDelta(runtimeStats.DatagramEnqueueBytes, previousRuntime.DatagramEnqueueBytes), counterDelta(runtimeStats.DatagramEnqueue, previousRuntime.DatagramEnqueue), elapsed)
				setRuntimeStage(&snapshot, diagnostics.QUICDatagramDequeue, runtimeStats.DatagramDequeueBytes, runtimeStats.DatagramDequeue, counterDelta(runtimeStats.DatagramDequeueBytes, previousRuntime.DatagramDequeueBytes), counterDelta(runtimeStats.DatagramDequeue, previousRuntime.DatagramDequeue), elapsed)
				setRuntimeStage(&snapshot, diagnostics.QUICPacketReceived, runtimeStats.QUICBytesReceived, runtimeStats.QUICPacketsReceived, counterDelta(runtimeStats.QUICBytesReceived, previousRuntime.QUICBytesReceived), counterDelta(runtimeStats.QUICPacketsReceived, previousRuntime.QUICPacketsReceived), elapsed)
				setRuntimeStage(&snapshot, diagnostics.QUICPacketPacked, runtimeStats.PackedBytes, runtimeStats.PacketsPacked, counterDelta(runtimeStats.PackedBytes, previousRuntime.PackedBytes), counterDelta(runtimeStats.PacketsPacked, previousRuntime.PacketsPacked), elapsed)
				setRuntimeStage(&snapshot, diagnostics.QUICPacketSent, runtimeStats.SendQueueDequeueBytes, runtimeStats.SendQueueDequeue, counterDelta(runtimeStats.SendQueueDequeueBytes, previousRuntime.SendQueueDequeueBytes), counterDelta(runtimeStats.SendQueueDequeue, previousRuntime.SendQueueDequeue), elapsed)
				setRuntimeStage(&snapshot, diagnostics.UDPWrite, runtimeStats.UDPWireBytes, runtimeStats.UDPWrites, counterDelta(runtimeStats.UDPWireBytes, previousRuntime.UDPWireBytes), counterDelta(runtimeStats.UDPWrites, previousRuntime.UDPWrites), elapsed)
				setRuntimeStage(&snapshot, diagnostics.UDPWire, runtimeStats.UDPWireBytes, runtimeStats.UDPWrites, counterDelta(runtimeStats.UDPWireBytes, previousRuntime.UDPWireBytes), counterDelta(runtimeStats.UDPWrites, previousRuntime.UDPWrites), elapsed)
				if baseline {
					snapshot.Warmup = true
					for stage, stats := range snapshot.Stages {
						stats.PacketsDelta, stats.BytesDelta = 0, 0
						stats.PacketsPerSecond, stats.BytesPerSecond, stats.Mbps = 0, 0, 0
						snapshot.Stages[stage] = stats
					}
				}
				snapshot.RefreshGaps()
				queueStats := mgr.AggregateQueueStats()
				tunStats := tun.Stats()
				writerStats := diagnostics.DATAGRAMWriterStats{
					TryCalls: datagramWriterTelemetry.tryCalls.Load(), PartialAccepts: datagramWriterTelemetry.partial.Load(),
					ZeroAccepts: datagramWriterTelemetry.zero.Load(), WritableWaits: datagramWriterTelemetry.waits.Load(),
					WritableWaitNS: datagramWriterTelemetry.waitNS.Load(), WritableWaitNSDelta: counterDelta(datagramWriterTelemetry.waitNS.Load(), previousWriterWaitNS), Cancelled: datagramWriterTelemetry.canceled.Load(),
				}
				logReleaseIntervalTelemetry(intervalElapsed, tunStats, previousTun, runtimeStats, previousRuntime, writerStats.WritableWaitNS, previousWriterWaitNS, baseline)
				snapshot.Runtime = diagnostics.RuntimeStats{
					DATAGRAMWriter: writerStats,
					QUIC: diagnostics.QUICStats{
						Connections: runtimeStats.Connections, CC: runtimeStats.CongestionController, CCState: runtimeStats.CongestionState,
						BBRConnections: runtimeStats.BBRConnections, BBRMode: runtimeStats.BBRMode,
						BBRBandwidthEstimate: runtimeStats.BBRBandwidthEstimate, BBRMinRTT: runtimeStats.BBRMinRTT.String(),
						BBRPacingGain: runtimeStats.BBRPacingGain, BBRCwndGain: runtimeStats.BBRCwndGain,
						BBRTargetCwnd: runtimeStats.BBRTargetCwnd, BBRRoundTripCount: runtimeStats.BBRRoundTripCount,
						BBRFullBandwidth: runtimeStats.BBRFullBandwidthReached, BBRRecovery: runtimeStats.BBRRecoveryState,
						BBRAppLimited: runtimeStats.BBRAppLimited,
						CWNDBytes:     runtimeStats.CongestionWindows, BytesInFlight: runtimeStats.BytesInFlight,
						PacingBytesPerSecond: runtimeStats.PacingRate, PacketsLost: runtimeStats.PacketsLost,
						BytesLost: runtimeStats.BytesLost, SpuriousLosses: runtimeStats.SpuriousLosses, ReorderingEvents: runtimeStats.ReorderingEvents,
						LossEvents: runtimeStats.LossEvents, LossByPacket: runtimeStats.LossByPacketThreshold,
						LossByTime: runtimeStats.LossByTimeThreshold, SpuriousPacket: runtimeStats.SpuriousAfterPacketThreshold,
						SpuriousTime: runtimeStats.SpuriousAfterTimeThreshold, CwndCutbacks: runtimeStats.CwndCutbacks,
						RecoveryDuration: runtimeStats.RecoveryDuration.String(), AdaptivePacket: runtimeStats.AdaptivePacketThreshold,
						AdaptiveTime:        runtimeStats.AdaptiveTimeThreshold.String(),
						MaxPacketReordering: runtimeStats.MaxPacketReordering, PacketsReceived: runtimeStats.QUICPacketsReceived,
						BytesReceived: runtimeStats.QUICBytesReceived, MaxTimeReordering: runtimeStats.MaxTimeReordering.String(),
						MinRTT: runtimeStats.MinRTT.String(), LatestRTT: runtimeStats.LatestRTT.String(),
						SmoothedRTT: runtimeStats.SmoothedRTT.String(), PMTU: runtimeStats.CurrentPMTU,
						GSOConnections: runtimeStats.GSOConnections,
					},
					Scheduler: diagnostics.SchedulerStats{
						Turns:                     schedulerCounter(runtimeStats.SchedulerTurns, previousRuntime.SchedulerTurns, baseline),
						TXTurns:                   schedulerCounter(runtimeStats.TXTurns, previousRuntime.TXTurns, baseline),
						TXPackets:                 schedulerCounter(runtimeStats.TXPackets, previousRuntime.TXPackets, baseline),
						TXBytes:                   schedulerCounter(runtimeStats.TXBytes, previousRuntime.TXBytes, baseline),
						RXTurns:                   schedulerCounter(runtimeStats.RXTurns, previousRuntime.RXTurns, baseline),
						RXPackets:                 schedulerCounter(runtimeStats.RXPackets, previousRuntime.RXPackets, baseline),
						TXTurnEndedDueToRXPending: schedulerCounter(runtimeStats.TXTurnEndedDueToRXPending, previousRuntime.TXTurnEndedDueToRXPending, baseline),
						SendScheduleRequests:      schedulerCounter(runtimeStats.SendScheduleRequests, previousRuntime.SendScheduleRequests, baseline),
						SendScheduleCoalesced:     schedulerCounter(runtimeStats.SendScheduleCoalesced, previousRuntime.SendScheduleCoalesced, baseline),
						YieldPacing:               schedulerCounter(runtimeStats.YieldPacing, previousRuntime.YieldPacing, baseline),
						YieldCWND:                 schedulerCounter(runtimeStats.YieldCwnd, previousRuntime.YieldCwnd, baseline),
						YieldSendQueue:            schedulerCounter(runtimeStats.YieldSendQueue, previousRuntime.YieldSendQueue, baseline),
						YieldNoData:               schedulerCounter(runtimeStats.YieldNoData, previousRuntime.YieldNoData, baseline),
						YieldPTO:                  schedulerCounter(runtimeStats.YieldPTO, previousRuntime.YieldPTO, baseline),
						YieldOther:                schedulerCounter(runtimeStats.YieldOther, previousRuntime.YieldOther, baseline),
					},
					GSO: diagnostics.GSOStats{
						UDPWrites:                schedulerCounter(runtimeStats.UDPWrites, previousRuntime.UDPWrites, baseline),
						GSOWrites:                schedulerCounter(runtimeStats.GSOWrites, previousRuntime.GSOWrites, baseline),
						NonGSOWrites:             schedulerCounter(runtimeStats.NonGSOWrites, previousRuntime.NonGSOWrites, baseline),
						GSOSegments:              schedulerCounter(runtimeStats.GSOSegments, previousRuntime.GSOSegments, baseline),
						GSOAttempts:              schedulerCounter(runtimeStats.GSOAttempts, previousRuntime.GSOAttempts, baseline),
						SingleSegment:            schedulerCounter(runtimeStats.SingleSegmentGSOAttempts, previousRuntime.SingleSegmentGSOAttempts, baseline),
						MultiSegmentWrites:       schedulerCounter(runtimeStats.GSOMultiSegmentWrites, previousRuntime.GSOMultiSegmentWrites, baseline),
						KernelFallbacks:          schedulerCounter(runtimeStats.GSOKernelFallbacks, previousRuntime.GSOKernelFallbacks, baseline),
						SendErrors:               schedulerCounter(runtimeStats.GSOSendErrors, previousRuntime.GSOSendErrors, baseline),
						SegmentsTotal:            schedulerCounter(runtimeStats.GSOSegmentsTotal, previousRuntime.GSOSegmentsTotal, baseline),
						SegmentsPerWrite:         segmentsPerWriteAverage(runtimeStats.SegmentsPerWriteBuckets),
						SegmentsP50:              segmentWritePercentile(runtimeStats.SegmentsPerWriteBuckets, 50),
						SegmentsP90:              segmentWritePercentile(runtimeStats.SegmentsPerWriteBuckets, 90),
						SegmentsP99:              segmentWritePercentile(runtimeStats.SegmentsPerWriteBuckets, 99),
						SegmentsMax:              segmentWritePercentile(runtimeStats.SegmentsPerWriteBuckets, 100),
						BytesPerWrite:            average(runtimeStats.UDPWireBytes, runtimeStats.UDPWrites),
						QUICPacketsPerWrite:      ratio(runtimeStats.PacketsPacked, runtimeStats.UDPWrites),
						IntervalBytesPerWrite:    average(intervalCounter(runtimeStats.UDPWireBytes, previousRuntime.UDPWireBytes, baseline), intervalCounter(runtimeStats.UDPWrites, previousRuntime.UDPWrites, baseline)),
						IntervalSegmentsPerWrite: segmentsPerWriteAverage(intervalSegmentBuckets),
						IntervalSegmentsP50:      segmentWritePercentile(intervalSegmentBuckets, 50),
						IntervalSegmentsP90:      segmentWritePercentile(intervalSegmentBuckets, 90),
						IntervalSegmentsP99:      segmentWritePercentile(intervalSegmentBuckets, 99),
						IntervalSegmentsMax:      segmentWritePercentile(intervalSegmentBuckets, 100),
						IntervalSegmentsBuckets:  intervalSegmentBuckets,
						FullPMTUPackets:          schedulerCounter(runtimeStats.FullPMTUPackets, previousRuntime.FullPMTUPackets, baseline),
						ShortPackets:             schedulerCounter(runtimeStats.ShortPackets, previousRuntime.ShortPackets, baseline),
						CandidatePackets:         schedulerCounter(runtimeStats.CandidateGSOBatchPackets, previousRuntime.CandidateGSOBatchPackets, baseline),
						BatchBreakShortPacket:    schedulerCounter(runtimeStats.GSOBatchBreakShortPacket, previousRuntime.GSOBatchBreakShortPacket, baseline),
						BatchBreakPacing:         schedulerCounter(runtimeStats.GSOBatchBreakPacing, previousRuntime.GSOBatchBreakPacing, baseline),
						BatchBreakCWND:           schedulerCounter(runtimeStats.GSOBatchBreakCwnd, previousRuntime.GSOBatchBreakCwnd, baseline),
						BatchBreakECN:            schedulerCounter(runtimeStats.GSOBatchBreakECN, previousRuntime.GSOBatchBreakECN, baseline),
						BatchBreakTXTurn:         schedulerCounter(runtimeStats.GSOBatchBreakTXTurn, previousRuntime.GSOBatchBreakTXTurn, baseline),
						BatchBreakBufferCapacity: schedulerCounter(runtimeStats.GSOBatchBreakBufferCapacity, previousRuntime.GSOBatchBreakBufferCapacity, baseline),
						BatchBreakNoData:         schedulerCounter(runtimeStats.GSOBatchBreakNoData, previousRuntime.GSOBatchBreakNoData, baseline),
						BatchBreakSendQueue:      schedulerCounter(runtimeStats.GSOBatchBreakSendQueue, previousRuntime.GSOBatchBreakSendQueue, baseline),
						PacketSizeBucketsTotal:   runtimeStats.PackedPacketSizeBuckets,
						PacketSizeBucketsDelta:   packetSizeDelta,
						PacketSizeBucketRanges:   [8]string{"<=256", "257-512", "513-768", "769-1024", "1025-1200", "1201-1280", "1281-1400", "1401+"},
					},
					Queues: diagnostics.QueueStats{
						Session: diagnostics.SessionQueueStats{Sessions: queueStats.Sessions, Capacity: queueStats.Capacity,
							Depth: queueStats.Depth, HighWater: queueStats.HighWater, Enqueued: queueStats.Enqueued,
							Dequeued: queueStats.Dequeued, Dropped: queueStats.Dropped},
						DATAGRAM: diagnostics.DATAGRAMQueueStats{Depth: runtimeStats.DatagramQueueDepth,
							HighWater: runtimeStats.DatagramQueueHighWater, BlockedEvents: runtimeStats.DatagramBlocked,
							BlockedDuration: runtimeStats.DatagramBlockedDuration.String()},
						SendQueue: diagnostics.SendQueueStats{Depth: runtimeStats.SendQueueDepth,
							HighWater: runtimeStats.SendQueueHighWater, HardBlockEvents: runtimeStats.SendQueueHardBlocks,
							HardBlockedDuration: runtimeStats.SendQueueHardBlockedDuration.String()},
					},
					TUN: diagnostics.TUNStats{RXPackets: tunStats.RXPackets, RXBytes: tunStats.RXBytes,
						TXPackets: tunStats.TXPackets, TXBytes: tunStats.TXBytes,
						RXBatches: tunStats.RXBatches, RXBatchPackets: tunStats.RXBatchPackets,
						RXBytesDelta: counterDelta(tunStats.RXBytes, previousTun.RXBytes), TXBytesDelta: counterDelta(tunStats.TXBytes, previousTun.TXBytes),
						RXMbps: rateMbps(counterDelta(tunStats.RXBytes, previousTun.RXBytes), elapsed), TXMbps: rateMbps(counterDelta(tunStats.TXBytes, previousTun.TXBytes), elapsed)},
				}
				previousRuntime = runtimeStats
				previousTun, previousWriterWaitNS = tunStats, writerStats.WritableWaitNS
				if cfg.Format == "json" {
					if encoded, err := snapshot.JSON(); err == nil {
						log.Printf("CONNECT-IP pipeline: %s", encoded)
					}
				} else {
					log.Printf("CONNECT-IP pipeline: interval=%s warmup=%t tun_rx_mbps=%.2f session_enqueue_mbps=%.2f session_writer_mbps=%.2f connectip_rx_mbps=%.2f udp_wire_mbps=%.2f cc=%s cwnd=%dB in_flight=%dB pacing=%dBps rtt_smoothed=%s lost=%d spurious=%d largest_gap=%s->%s/%.3f", snapshot.IntervalSecondsString(), snapshot.Warmup, snapshot.Stages[string(diagnostics.TunRead)].Mbps, snapshot.Stages[string(diagnostics.SessionEnqueue)].Mbps, snapshot.Stages[string(diagnostics.SessionWriterSubmit)].Mbps, snapshot.Stages[string(diagnostics.ConnectIPPacketReceived)].Mbps, snapshot.Stages[string(diagnostics.UDPWire)].Mbps, runtimeStats.CongestionController, runtimeStats.CongestionWindows, runtimeStats.BytesInFlight, runtimeStats.PacingRate, runtimeStats.SmoothedRTT, runtimeStats.PacketsLost, runtimeStats.SpuriousLosses, snapshot.LargestGap.From, snapshot.LargestGap.To, snapshot.LargestGap.Ratio)
				}
				continue
			}
			q := mgr.AggregateQueueStats()
			qs := mgr.AggregateRuntimeStats()
			t := tun.Stats()
			writerStats := diagnostics.DATAGRAMWriterStats{
				TryCalls: datagramWriterTelemetry.tryCalls.Load(), PartialAccepts: datagramWriterTelemetry.partial.Load(),
				ZeroAccepts: datagramWriterTelemetry.zero.Load(), WritableWaits: datagramWriterTelemetry.waits.Load(),
				WritableWaitNS: datagramWriterTelemetry.waitNS.Load(), WritableWaitNSDelta: counterDelta(datagramWriterTelemetry.waitNS.Load(), previousWriterWaitNS), Cancelled: datagramWriterTelemetry.canceled.Load(),
			}
			logReleaseIntervalTelemetry(intervalElapsed, t, previousTun, qs, previousRuntime, writerStats.WritableWaitNS, previousWriterWaitNS, false)
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			log.Printf("CONNECT-IP dataplane: sessions=%d queue_depth=%d/%d queue_high=%d enqueued=%d dequeued=%d dropped=%d tun_rx=%d/%dB tun_tx=%d/%dB tun_rx_batches=%d packets=%d quic_connections=%d cc=%s cc_state=%s cwnd=%dB in_flight=%dB pacing=%dBps rtt_min=%s rtt_latest=%s rtt_smoothed=%s lost=%d/%dB spurious=%d reorder=%d/%s datagram_queue=%d/%d enq=%d deq=%d enq_bytes=%d deq_bytes=%d nonempty=%s blocked=%d/%s send_queue=%d/%d enq=%d deq=%d enq_bytes=%d deq_bytes=%d hard_block=%d/%s packed=%d/%dB pacing_wakeups=%d udp_writes=%d udp_wire_bytes=%d gso_bytes=%d gso_writes=%d non_gso_writes=%d gso_segments=%d segments_per_write=%.2f/%d/%d/%d/%d rx_queue_drops=%d/%d pmtu=%d gso=%d heap=%dB gc=%d loss_events=%d loss_packet=%d loss_time=%d spurious_packet=%d spurious_time=%d cutbacks=%d recovery_duration=%s adaptive_packet_threshold=%d adaptive_time_threshold=%s gso_attempts_delta=%d single_segment_attempts_delta=%d datagram_try_batch_calls=%d datagram_partial_accepts=%d datagram_zero_accepts=%d datagram_writable_waits=%d datagram_writable_wait_ns=%d datagram_writable_cancelled=%d", q.Sessions, q.Depth, q.Capacity, q.HighWater, q.Enqueued, q.Dequeued, q.Dropped, t.RXPackets, t.RXBytes, t.TXPackets, t.TXBytes, t.RXBatches, t.RXBatchPackets, qs.Connections, qs.CongestionController, qs.CongestionState, qs.CongestionWindows, qs.BytesInFlight, qs.PacingRate, qs.MinRTT, qs.LatestRTT, qs.SmoothedRTT, qs.PacketsLost, qs.BytesLost, qs.SpuriousLosses, qs.MaxPacketReordering, qs.MaxTimeReordering, qs.DatagramQueueDepth, qs.DatagramQueueHighWater, qs.DatagramEnqueue, qs.DatagramDequeue, qs.DatagramEnqueueBytes, qs.DatagramDequeueBytes, qs.DatagramNonEmptyDuration, qs.DatagramBlocked, qs.DatagramBlockedDuration, qs.SendQueueDepth, qs.SendQueueHighWater, qs.SendQueueEnqueue, qs.SendQueueDequeue, qs.SendQueueEnqueueBytes, qs.SendQueueDequeueBytes, qs.SendQueueHardBlocks, qs.SendQueueHardBlockedDuration, qs.PacketsPacked, qs.PackedBytes, qs.PacingWakeups, qs.UDPWrites, qs.UDPWireBytes, qs.GSOBytes, qs.GSOWrites, qs.NonGSOWrites, qs.GSOSegments, segmentsPerWriteAverage(qs.SegmentsPerWriteBuckets), segmentWritePercentile(qs.SegmentsPerWriteBuckets, 50), segmentWritePercentile(qs.SegmentsPerWriteBuckets, 90), segmentWritePercentile(qs.SegmentsPerWriteBuckets, 99), segmentWritePercentile(qs.SegmentsPerWriteBuckets, 100), qs.ReceivedPacketQueueDrops, qs.ReceivedDatagramQueueDrops, qs.CurrentPMTU, qs.GSOConnections, mem.HeapAlloc, mem.NumGC, qs.LossEvents, qs.LossByPacketThreshold, qs.LossByTimeThreshold, qs.SpuriousAfterPacketThreshold, qs.SpuriousAfterTimeThreshold, qs.CwndCutbacks, qs.RecoveryDuration, qs.AdaptivePacketThreshold, qs.AdaptiveTimeThreshold, counterDelta(qs.GSOAttempts, previousRuntime.GSOAttempts), counterDelta(qs.SingleSegmentGSOAttempts, previousRuntime.SingleSegmentGSOAttempts), writerStats.TryCalls, writerStats.PartialAccepts, writerStats.ZeroAccepts, writerStats.WritableWaits, writerStats.WritableWaitNS, writerStats.Cancelled)
			if qs.BBRConnections > 0 {
				log.Printf("CONNECT-IP BBR: cc=%s bbr_mode=%s bbr_bw=%dbps bbr_min_rtt=%s bbr_pacing_gain=%.3f bbr_cwnd_gain=%.3f bbr_target_cwnd=%dB bbr_round=%d bbr_full_bw=%t bbr_recovery=%s bbr_app_limited=%t bbr_connections=%d", qs.CongestionController, qs.BBRMode, qs.BBRBandwidthEstimate, qs.BBRMinRTT, qs.BBRPacingGain, qs.BBRCwndGain, qs.BBRTargetCwnd, qs.BBRRoundTripCount, qs.BBRFullBandwidthReached, qs.BBRRecoveryState, qs.BBRAppLimited, qs.BBRConnections)
			}
			previousRuntime = qs
			previousTun, previousWriterWaitNS = t, writerStats.WritableWaitNS
		}
	}
}

func setRuntimeStage(snapshot *diagnostics.Stats, stage diagnostics.Stage, bytes, packets, bytesDelta, packetsDelta uint64, elapsed time.Duration) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return
	}
	bytesPerSecond := float64(bytesDelta) / seconds
	snapshot.Stages[string(stage)] = diagnostics.StageStats{
		PacketsTotal: packets, BytesTotal: bytes, PacketsDelta: packetsDelta, BytesDelta: bytesDelta,
		PacketsPerSecond: float64(packetsDelta) / seconds, BytesPerSecond: bytesPerSecond, Mbps: bytesPerSecond * 8 / 1e6,
	}
}

func logReleaseIntervalTelemetry(elapsed time.Duration, tunNow, tunBefore tunnel.Stats, q, qBefore session.AggregateRuntimeStats, waitNS, waitBefore uint64, warmup bool) {
	delta := func(now, before uint64) uint64 {
		if warmup {
			return 0
		}
		return counterDelta(now, before)
	}
	mbps := func(bytes uint64) float64 {
		if elapsed <= 0 {
			return 0
		}
		return float64(bytes) * 8 / elapsed.Seconds() / 1e6
	}
	rxBytes := delta(tunNow.RXBytes, tunBefore.RXBytes)
	txBytes := delta(tunNow.TXBytes, tunBefore.TXBytes)
	udpBytes := delta(q.UDPWireBytes, qBefore.UDPWireBytes)
	waitDelta := delta(waitNS, waitBefore)
	f := "CONNECT-IP dataplane interval: duration=%s warmup=%t tun_rx_bytes_delta=%d tun_tx_bytes_delta=%d tun_rx_mbps=%.2f tun_tx_mbps=%.2f udp_wire_bytes_delta=%d udp_wire_mbps=%.2f packets_packed_delta=%d udp_writes_delta=%d loss_delta=%d spurious_delta=%d reorder_delta=%d cwnd_cutbacks_delta=%d gso_attempts_delta=%d gso_single_segment_attempts_delta=%d gso_multi_writes_delta=%d gso_kernel_fallbacks_delta=%d gso_send_errors_delta=%d gso_segments_delta=%d datagram_writable_wait_duration_delta=%s gso_break_short_packet_delta=%d gso_break_pacing_delta=%d gso_break_cwnd_delta=%d gso_break_ecn_delta=%d gso_break_no_data_delta=%d gso_break_tx_turn_delta=%d gso_break_buffer_delta=%d gso_break_sendqueue_delta=%d"
	log.Printf(f, elapsed, warmup, rxBytes, txBytes, mbps(rxBytes), mbps(txBytes), udpBytes, mbps(udpBytes), delta(q.PacketsPacked, qBefore.PacketsPacked), delta(q.UDPWrites, qBefore.UDPWrites), delta(q.PacketsLost, qBefore.PacketsLost), delta(q.SpuriousLosses, qBefore.SpuriousLosses), delta(q.ReorderingEvents, qBefore.ReorderingEvents), delta(q.CwndCutbacks, qBefore.CwndCutbacks), delta(q.GSOAttempts, qBefore.GSOAttempts), delta(q.SingleSegmentGSOAttempts, qBefore.SingleSegmentGSOAttempts), delta(q.GSOMultiSegmentWrites, qBefore.GSOMultiSegmentWrites), delta(q.GSOKernelFallbacks, qBefore.GSOKernelFallbacks), delta(q.GSOSendErrors, qBefore.GSOSendErrors), delta(q.GSOSegmentsTotal, qBefore.GSOSegmentsTotal), time.Duration(waitDelta), delta(q.GSOBatchBreakShortPacket, qBefore.GSOBatchBreakShortPacket), delta(q.GSOBatchBreakPacing, qBefore.GSOBatchBreakPacing), delta(q.GSOBatchBreakCwnd, qBefore.GSOBatchBreakCwnd), delta(q.GSOBatchBreakECN, qBefore.GSOBatchBreakECN), delta(q.GSOBatchBreakNoData, qBefore.GSOBatchBreakNoData), delta(q.GSOBatchBreakTXTurn, qBefore.GSOBatchBreakTXTurn), delta(q.GSOBatchBreakBufferCapacity, qBefore.GSOBatchBreakBufferCapacity), delta(q.GSOBatchBreakSendQueue, qBefore.GSOBatchBreakSendQueue))
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

func schedulerCounter(total, previous uint64, baseline bool) diagnostics.CounterStats {
	if baseline {
		return diagnostics.CounterStats{Total: total}
	}
	return diagnostics.CounterStats{Total: total, Delta: counterDelta(total, previous)}
}

func average(total, count uint64) uint64 {
	if count == 0 {
		return 0
	}
	return total / count
}

func ratio(total, count uint64) float64 {
	if count == 0 {
		return 0
	}
	return float64(total) / float64(count)
}

func segmentsPerWriteAverage(buckets [65]uint64) float64 {
	var writes, segments uint64
	for i, count := range buckets {
		writes += count
		segments += uint64(i) * count
	}
	if writes == 0 {
		return 0
	}
	return float64(segments) / float64(writes)
}

func counterBucketDelta(current, previous [65]uint64) [65]uint64 {
	var delta [65]uint64
	for i := range current {
		delta[i] = counterDelta(current[i], previous[i])
	}
	return delta
}

func counterBucketDelta8(current, previous [8]uint64) [8]uint64 {
	var delta [8]uint64
	for i := range current {
		delta[i] = counterDelta(current[i], previous[i])
	}
	return delta
}

func intervalCounter(current, previous uint64, baseline bool) uint64 {
	if baseline {
		return 0
	}
	return counterDelta(current, previous)
}

func segmentWritePercentile(buckets [65]uint64, percentile uint64) uint64 {
	var total uint64
	for _, count := range buckets {
		total += count
	}
	if total == 0 {
		return 0
	}
	target := (total*percentile + 99) / 100
	var seen uint64
	for i, count := range buckets {
		seen += count
		if seen >= target {
			return uint64(i)
		}
	}
	return uint64(len(buckets) - 1)
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
	} else if probe := connectIPPipeline.Load(); probe != nil {
		probe.Add(diagnostics.SessionEnqueue, 1, uint64(len(pkt.Data)))
		probe.Add(diagnostics.TunDispatchSuccess, 1, uint64(len(pkt.Data)))
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
		if probe := connectIPPipeline.Load(); probe != nil {
			var bytes uint64
			for i := 0; i < n; i++ {
				bytes += uint64(sizes[i])
			}
			probe.Add(diagnostics.TunRead, uint64(n), bytes)
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
		if probe := connectIPPipeline.Load(); probe != nil {
			probe.Add(diagnostics.TunRead, 1, uint64(n))
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

type packetBufferTryOwnedWriter interface {
	TryWritePacketBufferOwned([]byte, int, int, connectip.PacketPayloadOwner) ([]byte, bool, error)
	DatagramWritable() <-chan struct{}
}

type packetBufferTryOwnedBatchWriter interface {
	TryWritePacketBuffersOwnedBatch([]connectip.OwnedPacketBuffer) (int, [][]byte, error)
	DatagramWritable() <-chan struct{}
}

type packetBufferWriter interface {
	WritePacketBuffer([]byte, int, int) ([]byte, error)
}

type sessionPacketWriter struct {
	conn   session.PacketConn
	batch  packetBufferTryOwnedBatchWriter
	try    packetBufferTryOwnedWriter
	owned  packetBufferOwnedWriter
	buffer packetBufferWriter
}

func newSessionPacketWriter(conn session.PacketConn) sessionPacketWriter {
	w := sessionPacketWriter{conn: conn}
	w.batch, _ = conn.(packetBufferTryOwnedBatchWriter)
	if w.batch == nil {
		w.try, _ = conn.(packetBufferTryOwnedWriter)
	}
	if w.batch == nil && w.try == nil {
		w.owned, _ = conn.(packetBufferOwnedWriter)
	}
	if w.batch == nil && w.try == nil && w.owned == nil {
		w.buffer, _ = conn.(packetBufferWriter)
	}
	return w
}

func (w sessionPacketWriter) writeBatch(s *session.Session, tun tunPacketWriter, packets []*session.PacketBuffer) bool {
	pending := packets
	var ownedScratch [sessionWriterDrainMax]connectip.OwnedPacketBuffer
	noProgressWakeups := 0
	for len(pending) > 0 {
		var items []connectip.OwnedPacketBuffer
		if len(pending) <= len(ownedScratch) {
			items = ownedScratch[:len(pending)]
		} else {
			items = make([]connectip.OwnedPacketBuffer, len(pending))
		}
		for i, pkt := range pending {
			items[i] = connectip.OwnedPacketBuffer{Buffer: pkt.Buffer, Offset: session.PacketPoolHeadroom, Length: len(pkt.Data), Owner: pkt}
		}
		datagramWriterTelemetry.tryCalls.Add(1)
		accepted, icmps, err := w.batch.TryWritePacketBuffersOwnedBatch(items)
		if accepted > 0 && accepted < len(pending) {
			datagramWriterTelemetry.partial.Add(1)
		}
		if accepted == 0 {
			datagramWriterTelemetry.zero.Add(1)
		}
		if accepted < 0 || accepted > len(pending) {
			releaseSessionPackets(s, pending)
			s.SetCloseReason("write-error")
			log.Printf("session=%d invalid batch acceptance count %d/%d", s.ID, accepted, len(pending))
			s.Close()
			return false
		}
		if probe := connectIPPipeline.Load(); probe != nil {
			for _, pkt := range pending[:accepted] {
				probe.Add(diagnostics.SessionWriterSubmit, 1, uint64(len(pkt.Data)))
				probe.Add(diagnostics.ConnectIPDatagramSubmit, 1, uint64(len(pkt.Data)))
				probe.Add(diagnostics.HTTP3DatagramSubmit, 1, uint64(len(pkt.Data)))
			}
		}
		for i := 0; i < accepted && i < len(icmps); i++ {
			icmp := icmps[i]
			if len(icmp) == 0 {
				continue
			}
			pkt := pending[i]
			if s.ShadowIP.IsValid() && s.ShadowIP != s.VisibleIP && !packet.TranslateICMP(icmp, s.VisibleIP, s.ShadowIP, true) {
				continue
			}
			if _, writeErr := tun.Write(icmp); writeErr != nil {
				releaseSessionPackets(s, pending[accepted:])
				s.SetCloseReason("tun-write-error")
				log.Printf("session=%d ICMP write failed: %v", s.ID, writeErr)
				s.Close()
				return false
			}
			_ = pkt // packet ownership was consumed with the ICMP response
		}
		if err != nil {
			releaseSessionPackets(s, pending[accepted:])
			if normalSessionError(err, s.Ctx) {
				return false
			}
			s.SetCloseReason("write-error")
			log.Printf("session=%d packet batch write failed: %v", s.ID, err)
			s.Close()
			return false
		}
		pending = pending[accepted:]
		if len(pending) == 0 {
			return true
		}
		if accepted > 0 {
			noProgressWakeups = 0
		}
		// A short prefix means the bounded transport queue ran out of room.
		// Let its writable notification drive progress instead of repeatedly
		// probing a known-full queue from this goroutine.
		if !waitDatagramWritable(s.Ctx, w.batch.DatagramWritable(), noProgressWakeups) {
			releaseSessionPackets(s, pending)
			return false
		}
		noProgressWakeups++
	}
	return true
}

// write sends one packet and follows the owned-send contract: a nil error
// transfers ownership; an error leaves it with this writer. connect-ip-go
// already releases synchronous rejected paths, and PacketBuffer.Release is
// deliberately idempotent, so releasing here also makes the generic optional
// interface safe for implementations that leave rejected ownership to us.
func (w sessionPacketWriter) write(s *session.Session, pkt *session.PacketBuffer) ([]byte, error) {
	if w.try != nil {
		noProgressWakeups := 0
		for {
			icmp, accepted, err := w.try.TryWritePacketBufferOwned(pkt.Buffer, session.PacketPoolHeadroom, len(pkt.Data), pkt)
			if !accepted {
				datagramWriterTelemetry.zero.Add(1)
			}
			if err != nil {
				s.ReleasePacket(pkt)
				return icmp, err
			}
			if accepted {
				return icmp, nil
			}
			if !waitDatagramWritable(s.Ctx, w.try.DatagramWritable(), noProgressWakeups) {
				s.ReleasePacket(pkt)
				return nil, s.Ctx.Err()
			}
			noProgressWakeups++
		}
	}
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

const datagramWritablePollInterval = 10 * time.Millisecond

// waitDatagramWritable tolerates transports that don't implement notifications
// and prevents a broken/already-closed notifier from creating an unbounded
// immediate retry loop. Proper generation channels still wake the first wait
// immediately, preserving the Try-then-Writable lost-wakeup contract.
func waitDatagramWritable(ctx context.Context, writable <-chan struct{}, noProgressWakeups int) bool {
	start := time.Now()
	datagramWriterTelemetry.waits.Add(1)
	defer func() { datagramWriterTelemetry.waitNS.Add(uint64(time.Since(start))) }()
	if writable == nil || noProgressWakeups > 0 {
		timer := time.NewTimer(datagramWritablePollInterval)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			datagramWriterTelemetry.canceled.Add(1)
			return false
		case <-timer.C:
			return true
		}
	}
	select {
	case <-ctx.Done():
		datagramWriterTelemetry.canceled.Add(1)
		return false
	case <-writable:
		return true
	}
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
		if probe := connectIPPipeline.Load(); probe != nil {
			var bytes uint64
			for _, pkt := range batch {
				bytes += uint64(len(pkt.Data))
			}
			probe.Add(diagnostics.SessionDequeue, uint64(len(batch)), bytes)
		}
		successful := 0
		if writer.batch != nil {
			if !writer.writeBatch(s, tun, batch) {
				return
			}
			s.Touch(time.Now())
			continue
		}
		for i, pkt := range batch {
			if s.Ctx.Err() != nil {
				if successful > 0 {
					s.Touch(time.Now())
				}
				releaseSessionPackets(s, batch[i:])
				return
			}
			icmp, err := writer.write(s, pkt)
			if probe := connectIPPipeline.Load(); probe != nil {
				probe.Add(diagnostics.SessionWriterSubmit, 1, uint64(len(pkt.Data)))
				if err == nil {
					probe.Add(diagnostics.ConnectIPDatagramSubmit, 1, uint64(len(pkt.Data)))
					probe.Add(diagnostics.HTTP3DatagramSubmit, 1, uint64(len(pkt.Data)))
				}
			}
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
				if probe := connectIPPipeline.Load(); probe != nil {
					probe.Add(diagnostics.ConnectIPPacketReceived, 1, uint64(len(pkt)))
					probe.Add(diagnostics.SessionReader, 1, uint64(len(pkt)))
				}
			}
		} else {
			pkt, err = s.Conn.ReadPacket()
			release = func() {}
			if err == nil {
				if probe := connectIPPipeline.Load(); probe != nil {
					probe.Add(diagnostics.ConnectIPPacketReceived, 1, uint64(len(pkt)))
					probe.Add(diagnostics.SessionReader, 1, uint64(len(pkt)))
				}
			}
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
						if probe := connectIPPipeline.Load(); probe != nil {
							probe.Add(diagnostics.ConnectIPPacketReceived, 1, uint64(len(next)))
							probe.Add(diagnostics.SessionReader, 1, uint64(len(next)))
						}
					}
				} else {
					next, pollErr = tryReader.TryReadPacket()
					nextRelease = func() {}
					if pollErr == nil {
						if probe := connectIPPipeline.Load(); probe != nil {
							probe.Add(diagnostics.ConnectIPPacketReceived, 1, uint64(len(next)))
							probe.Add(diagnostics.SessionReader, 1, uint64(len(next)))
						}
					}
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
				if probe := connectIPPipeline.Load(); probe != nil {
					probe.Add(diagnostics.TunWrite, 1, uint64(len(batch[0])))
				}
				_, err = tun.Write(batch[0])
			} else {
				if probe := connectIPPipeline.Load(); probe != nil {
					var bytes uint64
					for _, pkt := range batch {
						bytes += uint64(len(pkt))
					}
					probe.Add(diagnostics.TunWrite, uint64(len(batch)), bytes)
				}
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
