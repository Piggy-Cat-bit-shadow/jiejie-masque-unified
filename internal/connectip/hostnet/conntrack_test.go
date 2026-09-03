package hostnet

import (
	"net/netip"
	"testing"
)

func TestCleanupConntrackRejectsNonIPv4(t *testing.T) {
	if err := CleanupConntrack(netip.MustParseAddr("::1")); err == nil {
		t.Fatal("expected IPv6 rejection")
	}
}
