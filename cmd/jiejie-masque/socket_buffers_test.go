package main

import (
	"strings"
	"testing"
)

func TestFormatSocketBufferLogDistinguishesPreAndPostTuning(t *testing.T) {
	line := formatSocketBufferLog(socketBufferSizes{Receive: 1 << 20, Send: 1 << 20}, socketBufferSizes{Receive: 14680064, Send: 14680064}, 7340032)
	for _, want := range []string{"pre_rcv=1048576", "pre_send=1048576", "post_rcv=14680064", "post_send=14680064", "requested=7340032"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q does not contain %q", line, want)
		}
	}
}
