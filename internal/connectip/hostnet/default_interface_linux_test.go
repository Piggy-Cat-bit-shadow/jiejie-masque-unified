//go:build linux

package hostnet

import (
	"strings"
	"testing"
)

func TestParseIPv4DefaultRouteFixtures(t *testing.T) {
	const header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT"
	if got, err := parseIPv4DefaultRoute(strings.NewReader(header + "\neth9 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n")); err != nil || got != "eth9" {
		t.Fatalf("v4 route = %q, %v", got, err)
	}
	if _, err := parseIPv4DefaultRoute(strings.NewReader(header + "\nmalformed\n")); err == nil {
		t.Fatal("malformed v4 route was accepted")
	}
}

func TestParseIPv6DefaultRouteFixtures(t *testing.T) {
	zero := strings.Repeat("0", 32)
	line := zero + " 00 " + zero + " 00 00000000 00000000 00000000 00000000 00000000 eth6\n"
	if got, err := parseIPv6DefaultRoute(strings.NewReader(line)); err != nil || got != "eth6" {
		t.Fatalf("v6 route = %q, %v", got, err)
	}
	if _, err := parseIPv6DefaultRoute(strings.NewReader("bad\n")); err == nil {
		t.Fatal("malformed v6 route was accepted")
	}
}
