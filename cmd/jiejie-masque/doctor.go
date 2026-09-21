package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/hostnet"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/quicstate"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/tunnel"
)

type doctorLevel string

const (
	doctorPass doctorLevel = "PASS"
	doctorWarn doctorLevel = "WARN"
	doctorFail doctorLevel = "FAIL"
	doctorSkip doctorLevel = "SKIP"
)

type doctorResult struct {
	Name    string
	Level   doctorLevel
	Detail  string
	Failure bool
}

type doctorRunner func(context.Context, string, ...string) ([]byte, error)

type doctorRuntime struct {
	checkForwarding     func() error
	checkIPv6Forwarding func() error
	checkTunnel         func(string, netip.Prefix, int) error
	checkNAT            func(string, netip.Prefix) error
	checkIPv6Egress     func(string, netip.Prefix) error
	externalIface       func() (string, error)
	externalIface6      func() (string, error)
	lookPath            func(string) (string, error)
	run                 doctorRunner
	readFile            func(string) ([]byte, error)
	stat                func(string) (fs.FileInfo, error)
}

func defaultDoctorRuntime() doctorRuntime {
	return doctorRuntime{
		checkForwarding:     hostnet.CheckIPv4Forwarding,
		checkIPv6Forwarding: hostnet.CheckIPv6Forwarding,
		checkTunnel:         tunnel.CheckInterface,
		checkNAT:            hostnet.CheckNAT,
		checkIPv6Egress:     hostnet.CheckIPv6Egress,
		externalIface:       hostnet.DefaultExternalInterface,
		externalIface6:      hostnet.DefaultExternalInterface6,
		lookPath:            exec.LookPath,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		readFile: os.ReadFile,
		stat:     os.Stat,
	}
}

func runDoctor(out io.Writer, c config.Config, rt doctorRuntime) bool {
	results := doctorChecks(c, rt)
	hardFailure := false
	for _, result := range results {
		if result.Failure {
			hardFailure = true
		}
		if result.Detail == "" {
			fmt.Fprintf(out, "%s %s\n", result.Level, result.Name)
		} else {
			fmt.Fprintf(out, "%s %s: %s\n", result.Level, result.Name, result.Detail)
		}
	}
	if hardFailure {
		fmt.Fprintln(out, "doctor: FAIL")
	} else {
		fmt.Fprintln(out, "doctor: PASS")
	}
	return hardFailure
}

func doctorChecks(c config.Config, rt doctorRuntime) []doctorResult {
	results := []doctorResult{{Name: "config", Level: doctorPass}}
	addresses, err := c.ServerAddresses()
	if err != nil {
		return append(results, doctorResult{Name: "tunnel", Level: doctorFail, Detail: "invalid configured tunnel prefix", Failure: true})
	}
	if addresses.IPv4.IsValid() {
		if err := rt.checkForwarding(); err != nil {
			results = append(results, doctorResult{Name: "ipv4-forwarding", Level: doctorFail, Detail: err.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ipv4-forwarding", Level: doctorPass})
		}
	}
	if addresses.IPv6.IsValid() {
		if _, err := rt.lookPath("ip"); err != nil {
			results = append(results, doctorResult{Name: "ipv6-tun-config-tool", Level: doctorFail, Detail: "iproute2 command unavailable", Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ipv6-tun-config-tool", Level: doctorPass})
		}
		if err := rt.checkIPv6Forwarding(); err != nil {
			results = append(results, doctorResult{Name: "ipv6-forwarding", Level: doctorFail, Detail: err.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ipv6-forwarding", Level: doctorPass})
		}
	}
	for _, prefix := range addresses.Prefixes() {
		name := "ipv4-tun"
		if prefix.Addr().Is6() {
			name = "ipv6-tun"
		}
		if err := rt.checkTunnel("masque0", prefix, tunnelMTU); err != nil {
			results = append(results, doctorResult{Name: name, Level: doctorFail, Detail: err.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: name, Level: doctorPass, Detail: prefix.String()})
		}
	}
	external4 := c.HostNetwork.ExternalInterfaceIPv4
	if external4 == "" {
		external4 = c.HostNetwork.ExternalInterface
	}
	if external4 == "" && addresses.IPv4.IsValid() {
		var detectErr error
		external4, detectErr = rt.externalIface()
		if detectErr != nil {
			results = append(results, doctorResult{Name: "external-interface-ipv4", Level: doctorFail, Detail: detectErr.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "external-interface-ipv4", Level: doctorPass, Detail: external4})
		}
	} else if external4 != "" {
		results = append(results, doctorResult{Name: "external-interface-ipv4", Level: doctorPass, Detail: external4})
	}
	if addresses.IPv4.IsValid() {
		if external4 == "" {
			results = append(results, doctorResult{Name: "ipv4-nat", Level: doctorFail, Detail: "IPv4 external interface unavailable", Failure: true})
		} else if err := rt.checkNAT(external4, addresses.IPv4); err != nil {
			results = append(results, doctorResult{Name: "ipv4-nat", Level: doctorFail, Detail: err.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ipv4-nat", Level: doctorPass})
		}
	}
	external6 := c.HostNetwork.ExternalInterfaceIPv6
	if external6 == "" {
		external6 = c.HostNetwork.ExternalInterface
	}
	if external6 == "" && addresses.IPv6.IsValid() && c.Server.AdvertiseIPv6DefaultRoute && rt.externalIface6 != nil {
		var detectErr error
		external6, detectErr = rt.externalIface6()
		if detectErr != nil {
			results = append(results, doctorResult{Name: "external-interface-ipv6", Level: doctorFail, Detail: detectErr.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "external-interface-ipv6", Level: doctorPass, Detail: external6})
		}
	}
	if addresses.IPv6.IsValid() {
		if !config.IsUsableGlobalIPv6TunnelPrefix(addresses.IPv6) {
			results = append(results, doctorResult{Name: "ipv6-local-service", Level: doctorPass, Detail: "non-public IPv6 is valid for tunnel-local services only"}, doctorResult{Name: "ipv6-public-egress", Level: doctorWarn, Detail: "ULA/special-use prefix cannot provide public routed egress"})
		} else if !c.Server.AdvertiseIPv6DefaultRoute {
			results = append(results, doctorResult{Name: "ipv6-local-service", Level: doctorPass, Detail: "public IPv6 configured but ::/0 is not advertised"}, doctorResult{Name: "ipv6-public-egress", Level: doctorWarn, Detail: "public routed egress is not enabled for clients"})
		} else if external6 == "" || rt.checkIPv6Egress == nil {
			results = append(results, doctorResult{Name: "ipv6-local-egress-prerequisites", Level: doctorFail, Detail: "IPv6 egress checker or external interface unavailable", Failure: true})
		} else if err := rt.checkIPv6Egress(external6, addresses.IPv6); err != nil {
			results = append(results, doctorResult{Name: "ipv6-local-egress-prerequisites", Level: doctorFail, Detail: err.Error(), Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ipv6-local-egress-prerequisites", Level: doctorPass, Detail: "local routes/forwarding checked; upstream prefix return path is not proven"})
		}
		if c.Server.AdvertiseIPv6DefaultRoute {
			results = append(results, doctorResult{Name: "routed-prefix-return-path", Level: doctorWarn, Detail: "cannot prove the provider routes this IPv6 prefix back to the server from local inspection"})
		}
		if c.DNSGateway.IsEnabled() {
			results = append(results, doctorResult{Name: "ipv6-tunnel-dns-route", Level: doctorPass, Detail: "each IPv6-capable session receives the server DNS address as a host route"})
		} else {
			results = append(results, doctorResult{Name: "ipv6-tunnel-dns-route", Level: doctorSkip, Detail: "DNS gateway disabled"})
		}
	}
	results = append(results, doctorUFWChecks(c, external4, external6, rt, addresses)...)
	results = append(results, doctorResetKeyCheck(c.QUIC.StatelessResetKeyFile, rt))
	results = append(results, doctorUDPBufferChecks(rt)...)
	return results
}

const recommendedUDPBufferMax = 16 << 20

func doctorUDPBufferChecks(rt doctorRuntime) []doctorResult {
	readMax := func(path string) (int64, error) {
		b, err := rt.readFile(path)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	rmem, rerr := readMax("/proc/sys/net/core/rmem_max")
	wmem, werr := readMax("/proc/sys/net/core/wmem_max")
	if rerr != nil || werr != nil {
		return []doctorResult{{Name: "udp-buffer-sysctl", Level: doctorSkip, Detail: "Linux /proc sysctl values unavailable"}}
	}
	if rmem < recommendedUDPBufferMax || wmem < recommendedUDPBufferMax {
		return []doctorResult{{Name: "udp-buffer-sysctl", Level: doctorWarn, Detail: fmt.Sprintf("rmem_max=%d wmem_max=%d; 16777216 recommended for high-BDP WAN", rmem, wmem)}}
	}
	return []doctorResult{{Name: "udp-buffer-sysctl", Level: doctorPass, Detail: fmt.Sprintf("rmem_max=%d wmem_max=%d", rmem, wmem)}}
}

func doctorUFWChecks(c config.Config, external4, external6 string, rt doctorRuntime, addresses config.TunnelAddresses) []doctorResult {
	if _, err := rt.lookPath("ufw"); err != nil {
		return []doctorResult{{Name: "ufw", Level: doctorSkip, Detail: "command unavailable"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	status, err := rt.run(ctx, "ufw", "status", "verbose")
	cancel()
	if err != nil {
		return []doctorResult{{Name: "ufw", Level: doctorWarn, Detail: "status query failed"}}
	}
	if !strings.Contains(string(status), "Status: active") {
		return []doctorResult{{Name: "ufw", Level: doctorSkip, Detail: "inactive"}}
	}
	results := make([]doctorResult, 0, 5)
	if addresses.IPv6.IsValid() {
		b, readErr := rt.readFile("/etc/default/ufw")
		if readErr != nil || !ufwIPv6Enabled(b) {
			results = append(results, doctorResult{Name: "ufw-ipv6", Level: doctorFail, Detail: "UFW is active but /etc/default/ufw does not confirm IPV6=yes", Failure: true})
		} else {
			results = append(results, doctorResult{Name: "ufw-ipv6", Level: doctorPass, Detail: "IPV6=yes"})
		}
	}
	if (addresses.IPv4.IsValid() && external4 == "") || (addresses.IPv6.IsValid() && c.Server.AdvertiseIPv6DefaultRoute && external6 == "") {
		return []doctorResult{{Name: "ufw", Level: doctorFail, Detail: "external interface unavailable", Failure: true}}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	added, err := rt.run(ctx, "ufw", "show", "added")
	cancel()
	if err != nil {
		return []doctorResult{{Name: "ufw", Level: doctorWarn, Detail: "rule query failed"}}
	}
	rules := normalizedUFWRules(string(added))
	check := func(name, want string) doctorResult {
		if hasUFWRule(rules, want) {
			return doctorResult{Name: name, Level: doctorPass}
		}
		return doctorResult{Name: name, Level: doctorFail, Detail: "required project rule missing", Failure: true}
	}
	if c.DNSGateway.IsEnabled() {
		for _, address := range addresses.Addresses() {
			name := address.String()
			if address.Is4() {
				name = ""
			}
			udpName, tcpName := "ufw-dns-"+name+"udp", "ufw-dns-"+name+"tcp"
			results = append(results, check(udpName, fmt.Sprintf("allow in on masque0 to %s port %d proto udp comment jiejie-masque-connect-ip-dns", address, c.DNSGateway.Port)), check(tcpName, fmt.Sprintf("allow in on masque0 to %s port %d proto tcp comment jiejie-masque-connect-ip-dns", address, c.DNSGateway.Port)))
		}
	} else {
		results = append(results, doctorResult{Name: "ufw-dns", Level: doctorSkip, Detail: "DNS gateway disabled"})
	}
	for _, prefix := range addresses.Prefixes() {
		if prefix.Addr().Is6() && !c.Server.AdvertiseIPv6DefaultRoute {
			continue
		}
		name := "ufw-forward-" + prefix.String()
		external := external6
		if prefix.Addr().Is4() {
			name = "ufw-forward"
			external = external4
		}
		results = append(results, check(name, fmt.Sprintf("route allow in on masque0 out on %s from %s comment jiejie-masque-connect-ip-forward", external, prefix.Masked())))
	}
	return results
}

func ufwIPv6Enabled(contents []byte) bool {
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "IPV6" {
			value = strings.TrimSpace(strings.Trim(value, `"'`))
			return strings.EqualFold(value, "yes")
		}
	}
	return false
}

func normalizedUFWRules(added string) map[string]struct{} {
	rules := make(map[string]struct{})
	for _, line := range strings.Split(added, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "ufw "))
		line = strings.ReplaceAll(line, "'", "")
		if line != "" {
			rules[line] = struct{}{}
		}
	}
	return rules
}

func hasUFWRule(rules map[string]struct{}, want string) bool {
	_, ok := rules[want]
	return ok
}

func doctorResetKeyCheck(path string, rt doctorRuntime) doctorResult {
	if err := quicstate.ValidatePath(path); err != nil {
		return doctorResult{Name: "reset-key", Level: doctorFail, Detail: err.Error(), Failure: true}
	}
	b, err := rt.readFile(path)
	if os.IsNotExist(err) {
		return doctorResult{Name: "reset-key", Level: doctorWarn, Detail: "missing; service will create it"}
	}
	if err != nil {
		return doctorResult{Name: "reset-key", Level: doctorFail, Detail: "not readable", Failure: true}
	}
	if len(b) != quicstate.ResetKeySize {
		return doctorResult{Name: "reset-key", Level: doctorFail, Detail: fmt.Sprintf("invalid length %d", len(b)), Failure: true}
	}
	info, err := rt.stat(path)
	if err != nil {
		return doctorResult{Name: "reset-key", Level: doctorFail, Detail: "cannot stat", Failure: true}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return doctorResult{Name: "reset-key", Level: doctorWarn, Detail: "permissions are broader than 0600"}
	}
	return doctorResult{Name: "reset-key", Level: doctorPass}
}
