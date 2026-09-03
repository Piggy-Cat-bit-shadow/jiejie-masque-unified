package hostnet

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

func CleanupConntrack(ip netip.Addr) error {
	if !ip.Is4() {
		return fmt.Errorf("invalid conntrack address %s", ip)
	}
	for _, direction := range []string{"-s", "-d"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, "conntrack", "-D", direction, ip.String())
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("conntrack cleanup timeout for %s", ip)
			}
			if strings.Contains(string(out), "0 flow entries") || strings.Contains(string(out), "0 flow entry") {
				continue
			}
			return fmt.Errorf("conntrack cleanup %s %s: %w", direction, ip, err)
		}
	}
	return nil
}
