package main

import "testing"

type fakeCubicCongestionConnection struct{ calls int }

func (c *fakeCubicCongestionConnection) SetCubicCongestionControl() { c.calls++ }

func TestConfigureCongestionControl(t *testing.T) {
	conn := &fakeCubicCongestionConnection{}
	configureCongestionControl("default", conn)
	if conn.calls != 0 {
		t.Fatalf("default calls = %d, want 0", conn.calls)
	}
	configureCongestionControl("cubic", conn)
	if conn.calls != 1 {
		t.Fatalf("cubic calls = %d, want 1", conn.calls)
	}
}
