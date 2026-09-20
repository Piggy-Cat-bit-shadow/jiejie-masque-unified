package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/diagnostics"
)

// diagnoseReport consumes pipeline JSONL without retaining any raw line. It is
// intentionally a compact evidence summary, not an automatic root-cause claim.
func diagnoseReport(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	type aggregate struct {
		Samples  int
		Duration float64
		Peak     map[string]float64
		Sum      map[string]float64
		Gap      diagnostics.Gap
	}
	a := aggregate{Peak: map[string]float64{}, Sum: map[string]float64{}}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var snapshot diagnostics.Stats
		if err := json.Unmarshal(scanner.Bytes(), &snapshot); err != nil {
			return fmt.Errorf("parse pipeline JSONL: %w", err)
		}
		a.Samples++
		a.Duration += snapshot.IntervalSeconds
		for stage, stats := range snapshot.Stages {
			if stats.Mbps > a.Peak[stage] {
				a.Peak[stage] = stats.Mbps
			}
			a.Sum[stage] += stats.Mbps
		}
		if snapshot.LargestGap.Ratio > 0 && (a.Gap.Ratio == 0 || snapshot.LargestGap.Ratio < a.Gap.Ratio) {
			a.Gap = snapshot.LargestGap
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	fmt.Printf("Duration: %.1fs\nSamples: %d\n", a.Duration, a.Samples)
	fmt.Println("Stage peak Mbps:")
	for _, stage := range []string{"tun_read", "session_enqueue", "session_writer_submit", "connectip_datagram_submit", "http3_datagram_submit", "quic_packet_packed", "udp_wire"} {
		fmt.Printf("  %-32s %.2f\n", stage, a.Peak[stage])
	}
	if a.Gap.Ratio > 0 {
		fmt.Printf("Largest pipeline gap: %s -> %s (ratio %.3f)\n", a.Gap.From, a.Gap.To, a.Gap.Ratio)
	}
	if a.Peak["tun_read"] > 0 && a.Peak["session_enqueue"] < a.Peak["tun_read"]*0.75 {
		fmt.Println("Evidence summary: possible application/session handoff limit")
	}
	if a.Peak["quic_packet_packed"] > 0 && a.Peak["udp_wire"] < a.Peak["quic_packet_packed"]*0.75 {
		fmt.Println("Evidence summary: possible send scheduler or UDP handoff gap")
	}
	return nil
}
