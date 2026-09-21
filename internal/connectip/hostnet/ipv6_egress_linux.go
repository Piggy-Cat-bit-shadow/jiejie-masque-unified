//go:build linux

package hostnet

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CheckIPv6Egress validates local routed-egress prerequisites only. It cannot
// prove that a provider routes the tunnel prefix back to this host.
func CheckIPv6Egress(iface string, prefix netip.Prefix) error {
	if iface == "" {
		return fmt.Errorf("IPv6 external interface is not configured")
	}
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return fmt.Errorf("IPv6 external interface %q is unavailable: %w", iface, err)
	}
	if !usablePublicIPv6Prefix(prefix) {
		return fmt.Errorf("tunnel prefix %s is not a usable public IPv6 source prefix; ULA/on-link-only prefixes do not provide routed public egress", prefix)
	}
	if err := CheckIPv6Forwarding(); err != nil {
		return err
	}
	defaultIface, err := DefaultExternalInterface6()
	if err != nil {
		return fmt.Errorf("IPv6 default route: %w", err)
	}
	if defaultIface != iface {
		return fmt.Errorf("IPv6 default route uses %s, configured external interface is %s", defaultIface, iface)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-6", "route", "get", "2606:4700:4700::1111", "from", prefix.Addr().String()).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("IPv6 route lookup timed out")
		}
		return fmt.Errorf("IPv6 route lookup failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if !strings.Contains(" "+strings.TrimSpace(string(out))+" ", " dev "+iface+" ") {
		return fmt.Errorf("IPv6 route lookup from %s does not use %s: %s", prefix.Addr(), iface, strings.TrimSpace(string(out)))
	}
	return nil
}

func usablePublicIPv6Prefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return false
	}
	a := prefix.Addr()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsLoopback() || a.IsUnspecified() {
		return false
	}
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
	} {
		if p.Contains(a) || prefix.Contains(p.Addr()) {
			return false
		}
	}
	return true
}
