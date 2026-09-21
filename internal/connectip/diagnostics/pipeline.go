// Package diagnostics contains opt-in, identity-free CONNECT-IP pipeline
// counters. The disabled path is a nil check plus no allocation; snapshots
// are built from monotonic counters and fixed-size histograms.
package diagnostics

import (
	"encoding/json"
	"sync/atomic"
	"time"
)

type Stage string

const (
	TunRead                 Stage = "tun_read"
	TunDispatchSuccess      Stage = "tun_dispatch_success"
	SessionEnqueue          Stage = "session_enqueue"
	SessionDequeue          Stage = "session_dequeue"
	SessionWriterSubmit     Stage = "session_writer_submit"
	ConnectIPDatagramSubmit Stage = "connectip_datagram_submit"
	HTTP3DatagramSubmit     Stage = "http3_datagram_submit"
	QUICDatagramEnqueue     Stage = "quic_datagram_enqueue"
	QUICDatagramDequeue     Stage = "quic_datagram_dequeue"
	QUICPacketPacked        Stage = "quic_packet_packed"
	QUICPacketSent          Stage = "quic_packet_sent_to_sendqueue"
	UDPWrite                Stage = "udp_write"
	UDPWire                 Stage = "udp_wire"
	UDPRead                 Stage = "udp_read"
	QUICPacketReceived      Stage = "quic_packet_received"
	HTTP3DatagramReceived   Stage = "http3_datagram_received"
	ConnectIPPacketReceived Stage = "connectip_packet_received"
	SessionReader           Stage = "session_reader"
	TunWrite                Stage = "tun_write"
)

var stages = [...]Stage{
	TunRead, TunDispatchSuccess, SessionEnqueue, SessionDequeue,
	SessionWriterSubmit, ConnectIPDatagramSubmit, HTTP3DatagramSubmit,
	QUICDatagramEnqueue, QUICDatagramDequeue, QUICPacketPacked,
	QUICPacketSent, UDPWrite, UDPWire, UDPRead, QUICPacketReceived,
	HTTP3DatagramReceived, ConnectIPPacketReceived, SessionReader, TunWrite,
}

var downstreamStages = [...]Stage{
	TunRead, TunDispatchSuccess, SessionEnqueue, SessionDequeue,
	SessionWriterSubmit, ConnectIPDatagramSubmit, HTTP3DatagramSubmit,
	QUICDatagramEnqueue, QUICDatagramDequeue, QUICPacketPacked,
	QUICPacketSent, UDPWrite, UDPWire,
}

var upstreamStages = [...]Stage{
	UDPRead, QUICPacketReceived, HTTP3DatagramReceived,
	ConnectIPPacketReceived, SessionReader, TunWrite,
}

const histogramBuckets = 8

// Stats is a machine-readable interval snapshot. Rates are calculated from
// monotonic counter deltas; no identity, address, target, or payload is kept.
type Stats struct {
	SchemaVersion   int                   `json:"schema_version"`
	Timestamp       string                `json:"timestamp,omitempty"`
	IntervalSeconds float64               `json:"interval_seconds"`
	Warmup          bool                  `json:"warmup,omitempty"`
	Stages          map[string]StageStats `json:"stages"`
	Downstream      DirectionStats        `json:"downstream"`
	Upstream        DirectionStats        `json:"upstream"`
	LargestGap      Gap                   `json:"largest_pipeline_gap,omitempty"` // Deprecated: use directional gaps.
	DownstreamGap   Gap                   `json:"downstream_gap,omitempty"`
	UpstreamGap     Gap                   `json:"upstream_gap,omitempty"`
	Runtime         RuntimeStats          `json:"runtime,omitempty"`
}

type DirectionStats struct {
	TunRead                 StageStats `json:"tun_read,omitempty"`
	TunDispatch             StageStats `json:"tun_dispatch,omitempty"`
	SessionEnqueue          StageStats `json:"session_enqueue,omitempty"`
	SessionDequeue          StageStats `json:"session_dequeue,omitempty"`
	SessionWriterSubmit     StageStats `json:"session_writer_submit,omitempty"`
	ConnectIPDatagramSubmit StageStats `json:"connectip_datagram_submit,omitempty"`
	HTTP3DatagramSubmit     StageStats `json:"http3_datagram_submit,omitempty"`
	QUICDatagramEnqueue     StageStats `json:"quic_datagram_enqueue,omitempty"`
	QUICDatagramDequeue     StageStats `json:"quic_datagram_dequeue,omitempty"`
	QUICPacketPacked        StageStats `json:"quic_packet_packed,omitempty"`
	QUICPacketSent          StageStats `json:"quic_packet_sent,omitempty"`
	UDPWrite                StageStats `json:"udp_write,omitempty"`
	UDPWire                 StageStats `json:"udp_wire,omitempty"`
	UDPRead                 StageStats `json:"udp_read,omitempty"`
	QUICPacketReceived      StageStats `json:"quic_packet_received,omitempty"`
	HTTP3DatagramReceived   StageStats `json:"http3_datagram_received,omitempty"`
	ConnectIPPacketReceived StageStats `json:"connectip_packet_received,omitempty"`
	SessionReader           StageStats `json:"session_reader,omitempty"`
	TunWrite                StageStats `json:"tun_write,omitempty"`
}

type RuntimeStats struct {
	QUIC             QUICStats           `json:"quic"`
	Scheduler        SchedulerStats      `json:"scheduler"`
	GSO              GSOStats            `json:"gso"`
	Queues           QueueStats          `json:"queues"`
	DATAGRAMWriter   DATAGRAMWriterStats `json:"datagram_writer"`
	TUN              TUNStats            `json:"tun"`
	IPFamilies       IPFamilyStats       `json:"ip_families"`
	IPFamilyInterval IPFamilyStats       `json:"ip_family_interval"`
}

// IPFamilyStats contains aggregate, identity-free inner-packet counters.
type IPFamilyStats struct {
	IPv4RXPackets           uint64 `json:"inner_ipv4_rx_packets"`
	IPv4RXBytes             uint64 `json:"inner_ipv4_rx_bytes"`
	IPv6RXPackets           uint64 `json:"inner_ipv6_rx_packets"`
	IPv6RXBytes             uint64 `json:"inner_ipv6_rx_bytes"`
	IPv4TXPackets           uint64 `json:"inner_ipv4_tx_packets"`
	IPv4TXBytes             uint64 `json:"inner_ipv4_tx_bytes"`
	IPv6TXPackets           uint64 `json:"inner_ipv6_tx_packets"`
	IPv6TXBytes             uint64 `json:"inner_ipv6_tx_bytes"`
	IPv4ParseDrops          uint64 `json:"ipv4_drop_parse"`
	IPv6ParseDrops          uint64 `json:"ipv6_drop_parse"`
	IPv4NoSessionDrops      uint64 `json:"ipv4_drop_no_session"`
	IPv6NoSessionDrops      uint64 `json:"ipv6_drop_no_session"`
	IPv4PolicyDrops         uint64 `json:"ipv4_drop_policy"`
	IPv6PolicyDrops         uint64 `json:"ipv6_drop_policy"`
	ICMPv4FragNeeded        uint64 `json:"icmpv4_frag_needed_generated"`
	ICMPv6PacketTooBig      uint64 `json:"icmpv6_packet_too_big_generated"`
	IPv6ExtensionParseDrops uint64 `json:"ipv6_extension_parse_drop"`
}

func (s IPFamilyStats) Delta(previous IPFamilyStats) IPFamilyStats {
	d := func(now, before uint64) uint64 {
		if now < before {
			return now
		}
		return now - before
	}
	return IPFamilyStats{
		IPv4RXPackets: d(s.IPv4RXPackets, previous.IPv4RXPackets), IPv4RXBytes: d(s.IPv4RXBytes, previous.IPv4RXBytes),
		IPv6RXPackets: d(s.IPv6RXPackets, previous.IPv6RXPackets), IPv6RXBytes: d(s.IPv6RXBytes, previous.IPv6RXBytes),
		IPv4TXPackets: d(s.IPv4TXPackets, previous.IPv4TXPackets), IPv4TXBytes: d(s.IPv4TXBytes, previous.IPv4TXBytes),
		IPv6TXPackets: d(s.IPv6TXPackets, previous.IPv6TXPackets), IPv6TXBytes: d(s.IPv6TXBytes, previous.IPv6TXBytes),
		IPv4ParseDrops: d(s.IPv4ParseDrops, previous.IPv4ParseDrops), IPv6ParseDrops: d(s.IPv6ParseDrops, previous.IPv6ParseDrops),
		IPv4NoSessionDrops: d(s.IPv4NoSessionDrops, previous.IPv4NoSessionDrops), IPv6NoSessionDrops: d(s.IPv6NoSessionDrops, previous.IPv6NoSessionDrops),
		IPv4PolicyDrops: d(s.IPv4PolicyDrops, previous.IPv4PolicyDrops), IPv6PolicyDrops: d(s.IPv6PolicyDrops, previous.IPv6PolicyDrops),
		ICMPv4FragNeeded: d(s.ICMPv4FragNeeded, previous.ICMPv4FragNeeded), ICMPv6PacketTooBig: d(s.ICMPv6PacketTooBig, previous.ICMPv6PacketTooBig),
		IPv6ExtensionParseDrops: d(s.IPv6ExtensionParseDrops, previous.IPv6ExtensionParseDrops),
	}
}

type ipFamilyAtomic struct {
	values       [2][8]atomic.Uint64
	icmp4, icmp6 atomic.Uint64
}

type DATAGRAMWriterStats struct {
	TryCalls            uint64 `json:"try_batch_calls"`
	PartialAccepts      uint64 `json:"partial_accepts"`
	ZeroAccepts         uint64 `json:"zero_accepts"`
	WritableWaits       uint64 `json:"writable_wait_events"`
	WritableWaitNS      uint64 `json:"writable_wait_duration_ns"`
	WritableWaitNSDelta uint64 `json:"writable_wait_duration_delta_ns"`
	Cancelled           uint64 `json:"writable_cancelled"`
}

type GSOStats struct {
	UDPWrites                CounterStats `json:"udp_writes"`
	GSOWrites                CounterStats `json:"gso_writes"`
	NonGSOWrites             CounterStats `json:"non_gso_writes"`
	GSOSegments              CounterStats `json:"gso_segments"`
	GSOAttempts              CounterStats `json:"gso_attempts"`
	SingleSegment            CounterStats `json:"single_segment_attempts"`
	MultiSegmentWrites       CounterStats `json:"multi_segment_kernel_writes"`
	KernelFallbacks          CounterStats `json:"kernel_fallbacks"`
	SendErrors               CounterStats `json:"send_errors"`
	SegmentsTotal            CounterStats `json:"segments_total"`
	SegmentsPerWrite         float64      `json:"segments_per_write_avg"`
	SegmentsP50              uint64       `json:"segments_per_write_p50"`
	SegmentsP90              uint64       `json:"segments_per_write_p90"`
	SegmentsP99              uint64       `json:"segments_per_write_p99"`
	SegmentsMax              uint64       `json:"segments_per_write_max"`
	BytesPerWrite            uint64       `json:"bytes_per_write_avg"`
	QUICPacketsPerWrite      float64      `json:"quic_packets_per_write_avg"`
	IntervalBytesPerWrite    uint64       `json:"interval_bytes_per_write_avg"`
	IntervalSegmentsPerWrite float64      `json:"interval_segments_per_write_avg"`
	IntervalSegmentsP50      uint64       `json:"interval_segments_p50"`
	IntervalSegmentsP90      uint64       `json:"interval_segments_p90"`
	IntervalSegmentsP99      uint64       `json:"interval_segments_p99"`
	IntervalSegmentsMax      uint64       `json:"interval_segments_max"`
	IntervalSegmentsBuckets  [65]uint64   `json:"interval_segments_buckets"`
	FullPMTUPackets          CounterStats `json:"full_pmtu_packets"`
	ShortPackets             CounterStats `json:"short_packets"`
	CandidatePackets         CounterStats `json:"candidate_batch_packets"`
	BatchBreakShortPacket    CounterStats `json:"batch_break_short_packet"`
	BatchBreakPacing         CounterStats `json:"batch_break_pacing"`
	BatchBreakCWND           CounterStats `json:"batch_break_cwnd"`
	BatchBreakECN            CounterStats `json:"batch_break_ecn"`
	BatchBreakTXTurn         CounterStats `json:"batch_break_tx_turn"`
	BatchBreakBufferCapacity CounterStats `json:"batch_break_buffer_capacity"`
	BatchBreakNoData         CounterStats `json:"batch_break_no_data"`
	BatchBreakSendQueue      CounterStats `json:"batch_break_send_queue"`
	PacketSizeBucketsTotal   [8]uint64    `json:"packet_size_buckets_total"`
	PacketSizeBucketsDelta   [8]uint64    `json:"packet_size_buckets_delta"`
	PacketSizeBucketRanges   [8]string    `json:"packet_size_bucket_ranges"`
}

type QUICStats struct {
	Connections          uint64  `json:"connections"`
	CC                   string  `json:"cc"`
	CCState              string  `json:"cc_state"`
	BBRConnections       uint64  `json:"bbr_connections,omitempty"`
	BBRMode              string  `json:"bbr_mode,omitempty"`
	BBRBandwidthEstimate uint64  `json:"bbr_bandwidth_bits_per_second,omitempty"`
	BBRMinRTT            string  `json:"bbr_min_rtt,omitempty"`
	BBRPacingGain        float64 `json:"bbr_pacing_gain,omitempty"`
	BBRCwndGain          float64 `json:"bbr_cwnd_gain,omitempty"`
	BBRTargetCwnd        uint64  `json:"bbr_target_cwnd_bytes,omitempty"`
	BBRRoundTripCount    int64   `json:"bbr_round_trip_count,omitempty"`
	BBRFullBandwidth     bool    `json:"bbr_full_bandwidth_reached,omitempty"`
	BBRRecovery          string  `json:"bbr_recovery_state,omitempty"`
	BBRAppLimited        bool    `json:"bbr_app_limited,omitempty"`
	CWNDBytes            uint64  `json:"cwnd_bytes"`
	BytesInFlight        uint64  `json:"bytes_in_flight"`
	PacingBytesPerSecond uint64  `json:"pacing_bytes_per_second"`
	PacketsLost          uint64  `json:"packets_lost"`
	BytesLost            uint64  `json:"bytes_lost"`
	SpuriousLosses       uint64  `json:"spurious_losses"`
	ReorderingEvents     uint64  `json:"reordering_events"`
	LossEvents           uint64  `json:"loss_events"`
	LossByPacket         uint64  `json:"loss_by_packet_threshold"`
	LossByTime           uint64  `json:"loss_by_time_threshold"`
	SpuriousPacket       uint64  `json:"spurious_after_packet_threshold"`
	SpuriousTime         uint64  `json:"spurious_after_time_threshold"`
	CwndCutbacks         uint64  `json:"cwnd_cutbacks"`
	RecoveryDuration     string  `json:"recovery_duration"`
	AdaptivePacket       uint64  `json:"adaptive_packet_threshold"`
	AdaptiveTime         string  `json:"adaptive_time_threshold"`
	MaxPacketReordering  uint64  `json:"max_packet_reordering"`
	PacketsReceived      uint64  `json:"packets_received"`
	BytesReceived        uint64  `json:"bytes_received"`
	MaxTimeReordering    string  `json:"max_time_reordering"`
	MinRTT               string  `json:"min_rtt"`
	LatestRTT            string  `json:"latest_rtt"`
	SmoothedRTT          string  `json:"smoothed_rtt"`
	PMTU                 uint64  `json:"pmtu"`
	GSOConnections       uint64  `json:"gso_connections"`
}

type SchedulerStats struct {
	Turns                     CounterStats `json:"turns"`
	TXTurns                   CounterStats `json:"tx_turns"`
	TXPackets                 CounterStats `json:"tx_packets"`
	TXBytes                   CounterStats `json:"tx_bytes"`
	RXTurns                   CounterStats `json:"rx_turns"`
	RXPackets                 CounterStats `json:"rx_packets"`
	TXTurnEndedDueToRXPending CounterStats `json:"tx_turn_ended_due_to_rx_pending"`
	SendScheduleRequests      CounterStats `json:"send_schedule_requests"`
	SendScheduleCoalesced     CounterStats `json:"send_schedule_coalesced"`
	YieldPacing               CounterStats `json:"yield_pacing"`
	YieldCWND                 CounterStats `json:"yield_cwnd"`
	YieldSendQueue            CounterStats `json:"yield_send_queue"`
	YieldNoData               CounterStats `json:"yield_no_data"`
	YieldPTO                  CounterStats `json:"yield_pto"`
	YieldOther                CounterStats `json:"yield_other"`
}

type CounterStats struct {
	Total uint64 `json:"total"`
	Delta uint64 `json:"delta"`
}

type QueueStats struct {
	Session   SessionQueueStats  `json:"session"`
	DATAGRAM  DATAGRAMQueueStats `json:"datagram"`
	SendQueue SendQueueStats     `json:"send_queue"`
}

type SessionQueueStats struct {
	Sessions  uint64 `json:"sessions"`
	Capacity  uint64 `json:"capacity"`
	Depth     uint64 `json:"depth"`
	HighWater uint64 `json:"high_water"`
	Enqueued  uint64 `json:"enqueued"`
	Dequeued  uint64 `json:"dequeued"`
	Dropped   uint64 `json:"dropped"`
}

type DATAGRAMQueueStats struct {
	Depth           uint64 `json:"depth"`
	HighWater       uint64 `json:"high_water"`
	BlockedEvents   uint64 `json:"blocked_events"`
	BlockedDuration string `json:"blocked_duration"`
}

type SendQueueStats struct {
	Depth               uint64 `json:"depth"`
	HighWater           uint64 `json:"high_water"`
	HardBlockEvents     uint64 `json:"hard_block_events"`
	HardBlockedDuration string `json:"hard_blocked_duration"`
}

type TUNStats struct {
	RXPackets      uint64  `json:"rx_packets"`
	RXBytes        uint64  `json:"rx_bytes"`
	TXPackets      uint64  `json:"tx_packets"`
	TXBytes        uint64  `json:"tx_bytes"`
	RXBatches      uint64  `json:"rx_batches"`
	RXBatchPackets uint64  `json:"rx_batch_packets"`
	RXBytesDelta   uint64  `json:"rx_bytes_delta"`
	TXBytesDelta   uint64  `json:"tx_bytes_delta"`
	RXMbps         float64 `json:"rx_mbps"`
	TXMbps         float64 `json:"tx_mbps"`
}

type StageStats struct {
	PacketsTotal     uint64  `json:"packets_total"`
	BytesTotal       uint64  `json:"bytes_total"`
	PacketsDelta     uint64  `json:"packets_delta"`
	BytesDelta       uint64  `json:"bytes_delta"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	BytesPerSecond   float64 `json:"bytes_per_second"`
	Mbps             float64 `json:"mbps"`
	WaitP50US        uint64  `json:"wait_p50_us,omitempty"`
	WaitP90US        uint64  `json:"wait_p90_us,omitempty"`
	WaitP99US        uint64  `json:"wait_p99_us,omitempty"`
	WaitMaxUS        uint64  `json:"wait_max_us,omitempty"`
}

type Gap struct {
	From  string  `json:"from,omitempty"`
	To    string  `json:"to,omitempty"`
	Ratio float64 `json:"ratio,omitempty"`
}

type stageCounters struct {
	Packets atomic.Uint64
	Bytes   atomic.Uint64
	Wait    [histogramBuckets]atomic.Uint64
	WaitMax atomic.Uint64
}

// Probe is safe to share across all CONNECT-IP sessions and dataplane loops.
// A nil *Probe is the intended disabled fast path at call sites.
type Probe struct {
	stages   [len(stages)]stageCounters
	ipFamily ipFamilyAtomic
}

const (
	familyRXPackets = iota
	familyRXBytes
	familyTXPackets
	familyTXBytes
	familyParseDrops
	familyNoSessionDrops
	familyPolicyDrops
	familyExtensionDrops
)

func (p *Probe) AddInnerRX(packet []byte) { p.addInnerPacket(packet, true) }
func (p *Probe) AddInnerTX(packet []byte) { p.addInnerPacket(packet, false) }

func (p *Probe) addInnerPacket(packet []byte, rx bool) {
	if p == nil || len(packet) == 0 {
		return
	}
	family := int(packet[0] >> 4)
	if family != 4 && family != 6 {
		return
	}
	packets, bytes := familyRXPackets, familyRXBytes
	if !rx {
		packets, bytes = familyTXPackets, familyTXBytes
	}
	index := 0
	if family == 6 {
		index = 1
	}
	p.ipFamily.values[index][packets].Add(1)
	p.ipFamily.values[index][bytes].Add(uint64(len(packet)))
}

func (p *Probe) AddIPDrop(version uint8, parse, noSession, extension bool) {
	if p == nil || (version != 4 && version != 6) {
		return
	}
	index := 0
	if version == 6 {
		index = 1
	}
	if parse {
		p.ipFamily.values[index][familyParseDrops].Add(1)
	}
	if noSession {
		p.ipFamily.values[index][familyNoSessionDrops].Add(1)
	}
	if !parse && !noSession {
		p.ipFamily.values[index][familyPolicyDrops].Add(1)
	}
	if extension {
		p.ipFamily.values[1][familyExtensionDrops].Add(1)
	}
}

func (p *Probe) AddGeneratedICMP(packet []byte) {
	if p == nil || len(packet) < 2 {
		return
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 22 && packet[9] == 1 && packet[20] == 3 && packet[21] == 4 {
			p.ipFamily.icmp4.Add(1)
		}
	case 6:
		if len(packet) >= 41 && packet[6] == 58 && packet[40] == 2 {
			p.ipFamily.icmp6.Add(1)
		}
	}
}

func (p *Probe) IPFamilySnapshot() IPFamilyStats {
	if p == nil {
		return IPFamilyStats{}
	}
	v4, v6 := &p.ipFamily.values[0], &p.ipFamily.values[1]
	return IPFamilyStats{IPv4RXPackets: v4[familyRXPackets].Load(), IPv4RXBytes: v4[familyRXBytes].Load(), IPv6RXPackets: v6[familyRXPackets].Load(), IPv6RXBytes: v6[familyRXBytes].Load(), IPv4TXPackets: v4[familyTXPackets].Load(), IPv4TXBytes: v4[familyTXBytes].Load(), IPv6TXPackets: v6[familyTXPackets].Load(), IPv6TXBytes: v6[familyTXBytes].Load(), IPv4ParseDrops: v4[familyParseDrops].Load(), IPv6ParseDrops: v6[familyParseDrops].Load(), IPv4NoSessionDrops: v4[familyNoSessionDrops].Load(), IPv6NoSessionDrops: v6[familyNoSessionDrops].Load(), IPv4PolicyDrops: v4[familyPolicyDrops].Load(), IPv6PolicyDrops: v6[familyPolicyDrops].Load(), ICMPv4FragNeeded: p.ipFamily.icmp4.Load(), ICMPv6PacketTooBig: p.ipFamily.icmp6.Load(), IPv6ExtensionParseDrops: v6[familyExtensionDrops].Load()}
}

func (p *Probe) index(stage Stage) (int, bool) {
	for i, candidate := range stages {
		if candidate == stage {
			return i, true
		}
	}
	return 0, false
}

func (p *Probe) Add(stage Stage, packets, bytes uint64) {
	if p == nil {
		return
	}
	i, ok := p.index(stage)
	if !ok {
		return
	}
	p.stages[i].Packets.Add(packets)
	p.stages[i].Bytes.Add(bytes)
}

func (p *Probe) ObserveWait(stage Stage, d time.Duration) {
	if p == nil {
		return
	}
	i, ok := p.index(stage)
	if !ok {
		return
	}
	us := uint64(d / time.Microsecond)
	if us == 0 {
		us = 1
	}
	b := 0
	for limit := uint64(10); b < histogramBuckets-1 && us > limit; limit *= 2 {
		b++
	}
	p.stages[i].Wait[b].Add(1)
	for {
		old := p.stages[i].WaitMax.Load()
		if us <= old || p.stages[i].WaitMax.CompareAndSwap(old, us) {
			break
		}
	}
}

type Point struct{ Packets, Bytes uint64 }

// Snapshot returns deltas since the previous snapshot held by the caller.
// The previous map must be retained only by the diagnostic goroutine.
func (p *Probe) Snapshot(previous map[Stage]Point, elapsed time.Duration) (Stats, map[Stage]Point) {
	if elapsed <= 0 {
		elapsed = time.Second
	}
	seconds := elapsed.Seconds()
	out := Stats{SchemaVersion: 2, IntervalSeconds: seconds, Warmup: previous == nil, Stages: make(map[string]StageStats, len(stages))}
	now := make(map[Stage]Point, len(stages))
	rates := make(map[Stage]float64, len(stages))
	for i, stage := range stages {
		packets := p.stages[i].Packets.Load()
		bytes := p.stages[i].Bytes.Load()
		old := previous[stage]
		packetsDelta, bytesDelta := packets-old.Packets, bytes-old.Bytes
		if out.Warmup {
			packetsDelta, bytesDelta = 0, 0
		}
		ps := float64(packetsDelta) / seconds
		bs := float64(bytesDelta) / seconds
		out.Stages[string(stage)] = StageStats{PacketsTotal: packets, BytesTotal: bytes, PacketsDelta: packetsDelta, BytesDelta: bytesDelta, PacketsPerSecond: ps, BytesPerSecond: bs, Mbps: bs * 8 / 1e6, WaitP50US: p.quantile(i, 0.50), WaitP90US: p.quantile(i, 0.90), WaitP99US: p.quantile(i, 0.99), WaitMaxUS: p.stages[i].WaitMax.Load()}
		now[stage] = Point{Packets: packets, Bytes: bytes}
		rates[stage] = bs
	}
	out.DownstreamGap = largestAdjacentGap(downstreamStages[:], rates)
	out.UpstreamGap = largestAdjacentGap(upstreamStages[:], rates)
	out.refreshDirections()
	out.LargestGap = out.DownstreamGap
	if out.LargestGap.Ratio == 0 || (out.UpstreamGap.Ratio > 0 && out.UpstreamGap.Ratio < out.LargestGap.Ratio) {
		out.LargestGap = out.UpstreamGap
	}
	return out, now
}

func largestAdjacentGap(ordered []Stage, rates map[Stage]float64) Gap {
	var largest Gap
	for i := 1; i < len(ordered); i++ {
		left, right := rates[ordered[i-1]], rates[ordered[i]]
		if left <= 0 || right <= 0 {
			continue
		}
		ratio := right / left
		if largest.Ratio == 0 || ratio < largest.Ratio {
			largest = Gap{From: string(ordered[i-1]), To: string(ordered[i]), Ratio: ratio}
		}
	}
	return largest
}

// RefreshGaps recomputes only adjacent same-direction stage gaps. It is useful
// after aggregate runtime counters have been merged into a probe snapshot.
func (s *Stats) RefreshGaps() {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = 2
	}
	rates := make(map[Stage]float64, len(stages))
	for _, stage := range stages {
		rates[stage] = s.Stages[string(stage)].BytesPerSecond
	}
	s.DownstreamGap = largestAdjacentGap(downstreamStages[:], rates)
	s.UpstreamGap = largestAdjacentGap(upstreamStages[:], rates)
	s.LargestGap = s.DownstreamGap
	if s.LargestGap.Ratio == 0 || (s.UpstreamGap.Ratio > 0 && s.UpstreamGap.Ratio < s.LargestGap.Ratio) {
		s.LargestGap = s.UpstreamGap
	}
	s.refreshDirections()
}

func (s *Stats) refreshDirections() {
	stage := func(name Stage) StageStats { return s.Stages[string(name)] }
	s.Downstream = DirectionStats{
		TunRead: stage(TunRead), TunDispatch: stage(TunDispatchSuccess),
		SessionEnqueue: stage(SessionEnqueue), SessionDequeue: stage(SessionDequeue),
		SessionWriterSubmit: stage(SessionWriterSubmit), ConnectIPDatagramSubmit: stage(ConnectIPDatagramSubmit),
		HTTP3DatagramSubmit: stage(HTTP3DatagramSubmit), QUICDatagramEnqueue: stage(QUICDatagramEnqueue),
		QUICDatagramDequeue: stage(QUICDatagramDequeue), QUICPacketPacked: stage(QUICPacketPacked),
		QUICPacketSent: stage(QUICPacketSent), UDPWrite: stage(UDPWrite), UDPWire: stage(UDPWire),
	}
	s.Upstream = DirectionStats{
		UDPRead: stage(UDPRead), QUICPacketReceived: stage(QUICPacketReceived),
		HTTP3DatagramReceived: stage(HTTP3DatagramReceived), ConnectIPPacketReceived: stage(ConnectIPPacketReceived),
		SessionReader: stage(SessionReader), TunWrite: stage(TunWrite),
	}
}

func (p *Probe) quantile(i int, q float64) uint64 {
	var total uint64
	for b := range p.stages[i].Wait {
		total += p.stages[i].Wait[b].Load()
	}
	if total == 0 {
		return 0
	}
	target := uint64(float64(total-1)*q) + 1
	var seen uint64
	limits := [...]uint64{10, 20, 40, 80, 160, 320, 640, ^uint64(0)}
	for b, limit := range limits {
		seen += p.stages[i].Wait[b].Load()
		if seen >= target {
			return limit
		}
	}
	return 0
}

func (s Stats) JSON() ([]byte, error) { return json.Marshal(s) }

func (s Stats) IntervalSecondsString() string {
	return time.Duration(s.IntervalSeconds * float64(time.Second)).String()
}

func (s StageStats) WaitQuantiles() (uint64, uint64, uint64) {
	return s.WaitP50US, s.WaitP90US, s.WaitP99US
}
