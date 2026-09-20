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
	Timestamp       string                `json:"timestamp,omitempty"`
	IntervalSeconds float64               `json:"interval_seconds"`
	Warmup          bool                  `json:"warmup,omitempty"`
	Stages          map[string]StageStats `json:"stages"`
	Downstream      DirectionStats        `json:"downstream"`
	Upstream        DirectionStats        `json:"upstream"`
	LargestGap      Gap                   `json:"largest_pipeline_gap,omitempty"`
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
	QUIC      QUICStats      `json:"quic"`
	Scheduler SchedulerStats `json:"scheduler"`
	GSO       GSOStats       `json:"gso"`
	Queues    QueueStats     `json:"queues"`
	TUN       TUNStats       `json:"tun"`
}

type GSOStats struct {
	UDPWrites           CounterStats `json:"udp_writes"`
	GSOWrites           CounterStats `json:"gso_writes"`
	NonGSOWrites        CounterStats `json:"non_gso_writes"`
	GSOSegments         CounterStats `json:"gso_segments"`
	SegmentsPerWrite    float64      `json:"segments_per_write_avg"`
	SegmentsP50         uint64       `json:"segments_per_write_p50"`
	SegmentsP90         uint64       `json:"segments_per_write_p90"`
	SegmentsP99         uint64       `json:"segments_per_write_p99"`
	SegmentsMax         uint64       `json:"segments_per_write_max"`
	BytesPerWrite       uint64       `json:"bytes_per_write_avg"`
	QUICPacketsPerWrite float64      `json:"quic_packets_per_write_avg"`
}

type QUICStats struct {
	Connections          uint64 `json:"connections"`
	CC                   string `json:"cc"`
	CCState              string `json:"cc_state"`
	CWNDBytes            uint64 `json:"cwnd_bytes"`
	BytesInFlight        uint64 `json:"bytes_in_flight"`
	PacingBytesPerSecond uint64 `json:"pacing_bytes_per_second"`
	PacketsLost          uint64 `json:"packets_lost"`
	BytesLost            uint64 `json:"bytes_lost"`
	SpuriousLosses       uint64 `json:"spurious_losses"`
	MaxPacketReordering  uint64 `json:"max_packet_reordering"`
	PacketsReceived      uint64 `json:"packets_received"`
	BytesReceived        uint64 `json:"bytes_received"`
	MaxTimeReordering    string `json:"max_time_reordering"`
	MinRTT               string `json:"min_rtt"`
	LatestRTT            string `json:"latest_rtt"`
	SmoothedRTT          string `json:"smoothed_rtt"`
	PMTU                 uint64 `json:"pmtu"`
	GSOConnections       uint64 `json:"gso_connections"`
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
	RXPackets      uint64 `json:"rx_packets"`
	RXBytes        uint64 `json:"rx_bytes"`
	TXPackets      uint64 `json:"tx_packets"`
	TXBytes        uint64 `json:"tx_bytes"`
	RXBatches      uint64 `json:"rx_batches"`
	RXBatchPackets uint64 `json:"rx_batch_packets"`
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
	stages [len(stages)]stageCounters
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
	out := Stats{IntervalSeconds: seconds, Warmup: previous == nil, Stages: make(map[string]StageStats, len(stages))}
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
