package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

type conntrackRunner func(context.Context, ...string) ([]byte, error)

func CleanupConntrack(ip netip.Addr) error {
	return cleanupConntrackWithOptions(ip, 2*time.Second, runConntrack)
}

func runConntrack(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "conntrack", args...).CombinedOutput()
}

func cleanupConntrackWithOptions(ip netip.Addr, timeout time.Duration, runner conntrackRunner) error {
	if !ip.Is4() {
		return fmt.Errorf("invalid conntrack address %s", ip)
	}
	for _, direction := range []string{"-s", "-d"} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		out, err := runner(ctx, "-D", direction, ip.String())
		ctxErr := ctx.Err()
		cancel()
		if err != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				return fmt.Errorf("conntrack cleanup timeout for %s: %w", ip, context.DeadlineExceeded)
			}
			if conntrackNoMatch(out) {
				continue
			}
			return fmt.Errorf("conntrack cleanup %s %s: %w", direction, ip, err)
		}
	}
	return nil
}

func conntrackNoMatch(out []byte) bool {
	text := strings.ToLower(string(out))
	return strings.Contains(text, "0 flow entries") || strings.Contains(text, "0 flow entry")
}
