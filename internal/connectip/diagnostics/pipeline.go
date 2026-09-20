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
	LargestGap      Gap                   `json:"largest_pipeline_gap,omitempty"`
	DownstreamGap   Gap                   `json:"downstream_gap,omitempty"`
	UpstreamGap     Gap                   `json:"upstream_gap,omitempty"`
	Runtime         any                   `json:"runtime,omitempty"`
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
