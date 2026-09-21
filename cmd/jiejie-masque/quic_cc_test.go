package main

import "testing"

type fakeCubicCongestionConnection struct{ cubicCalls, bbrCalls int }

func (c *fakeCubicCongestionConnection) SetCubicCongestionControl() { c.cubicCalls++ }
func (c *fakeCubicCongestionConnection) SetBBRCongestionControl()   { c.bbrCalls++ }

func TestConfigureCongestionControl(t *testing.T) {
	conn := &fakeCubicCongestionConnection{}
	if err := configureCongestionControl("default", conn); err != nil {
		t.Fatal(err)
	}
	if conn.cubicCalls != 0 || conn.bbrCalls != 0 {
		t.Fatalf("default calls = cubic:%d bbr:%d, want both 0", conn.cubicCalls, conn.bbrCalls)
	}
	if err := configureCongestionControl("cubic", conn); err != nil {
		t.Fatal(err)
	}
	if conn.cubicCalls != 1 || conn.bbrCalls != 0 {
		t.Fatalf("cubic calls = cubic:%d bbr:%d, want 1/0", conn.cubicCalls, conn.bbrCalls)
	}
	if err := configureCongestionControl("bbr", conn); err != nil {
		t.Fatal(err)
	}
	if conn.bbrCalls != 1 {
		t.Fatalf("bbr calls = %d, want 1", conn.bbrCalls)
	}
	if err := configureCongestionControl("unknown", conn); err == nil {
		t.Fatal("unknown controller accepted")
	}
}
