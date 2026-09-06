package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/quicstate"
)

type doctorTestInfo struct{ mode fs.FileMode }

func (i doctorTestInfo) Name() string       { return "reset.key" }
func (i doctorTestInfo) Size() int64        { return int64(quicstate.ResetKeySize) }
func (i doctorTestInfo) Mode() fs.FileMode  { return i.mode }
func (i doctorTestInfo) ModTime() time.Time { return time.Time{} }
func (i doctorTestInfo) IsDir() bool        { return false }
func (i doctorTestInfo) Sys() any           { return nil }

func doctorTestConfig(dns bool) config.Config {
	return config.Config{
		Mode:       "connect-ip",
		QUIC:       config.QUIC{StatelessResetKeyFile: "/var/lib/jiejie-masque-connect-ip/stateless-reset.key"},
		Server:     config.Server{TunnelIPv4: "10.200.0.1/16", MTU: 1280},
		DNSGateway: config.DNSGateway{Enabled: &dns, Port: 5353},
	}
}

func doctorTestRuntime(t *testing.T, ufwStatus, added string) (*doctorRuntime, *[]string) {
	t.Helper()
	calls := []string{}
	rt := &doctorRuntime{
		checkForwarding: func() error { return nil },
		checkTunnel:     func(string, netip.Prefix, int) error { return nil },
		checkNAT:        func(string, netip.Prefix) error { return nil },
		externalIface:   func() (string, error) { return "eth0", nil },
		lookPath:        func(string) (string, error) { return "/usr/sbin/ufw", nil },
		readFile:        func(string) ([]byte, error) { return make([]byte, quicstate.ResetKeySize), nil },
		stat:            func(string) (fs.FileInfo, error) { return doctorTestInfo{mode: 0o600}, nil },
	}
	rt.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+args[0]+" "+args[1])
		if args[0] == "status" {
			return []byte(ufwStatus), nil
		}
		return []byte(added), nil
	}
	return rt, &calls
}

func TestDoctorPassAndReadOnlyCommands(t *testing.T) {
	dns := true
	c := doctorTestConfig(dns)
	added := "ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'\n" +
		"ufw allow in on masque0 to 10.200.0.1 port 5353 proto tcp comment 'jiejie-masque-connect-ip-dns'\n" +
		"ufw route allow in on masque0 out on eth0 from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'\n"
	rt, calls := doctorTestRuntime(t, "Status: active\n", added)
	var out bytes.Buffer
	if failed := runDoctor(&out, c, *rt); failed {
		t.Fatalf("doctor unexpectedly failed:\n%s", out.String())
	}
	if got, want := out.String(), "doctor: PASS\n"; !bytes.Contains([]byte(got), []byte(want)) {
		t.Fatalf("output missing %q: %s", want, got)
	}
	if len(*calls) != 2 || (*calls)[0] != "ufw status verbose" || (*calls)[1] != "ufw show added" {
		t.Fatalf("commands = %v; doctor must only query UFW", *calls)
	}
}

func TestDoctorHardFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*doctorRuntime)
	}{
		{"forwarding", func(rt *doctorRuntime) { rt.checkForwarding = func() error { return errors.New("disabled") } }},
		{"tun-missing", func(rt *doctorRuntime) {
			rt.checkTunnel = func(string, netip.Prefix, int) error { return errors.New("masque0 missing") }
		}},
		{"tun-mtu", func(rt *doctorRuntime) {
			rt.checkTunnel = func(string, netip.Prefix, int) error { return errors.New("MTU mismatch") }
		}},
		{"nat", func(rt *doctorRuntime) {
			rt.checkNAT = func(string, netip.Prefix) error { return errors.New("missing") }
		}},
		{"reset-key-length", func(rt *doctorRuntime) { rt.readFile = func(string) ([]byte, error) { return []byte("short"), nil } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := doctorTestRuntime(t, "Status: inactive", "")
			tc.mutate(rt)
			var out bytes.Buffer
			if !runDoctor(&out, doctorTestConfig(true), *rt) {
				t.Fatalf("doctor did not fail: %s", out.String())
			}
		})
	}
}

func TestDoctorUFWStatesAndContracts(t *testing.T) {
	dns := true
	c := doctorTestConfig(dns)
	activeRules := "ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'\n" +
		"ufw allow in on masque0 to 10.200.0.1 port 5353 proto tcp comment 'jiejie-masque-connect-ip-dns'\n" +
		"ufw route allow in on masque0 out on eth0 from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'\n"
	for _, tc := range []struct {
		name, status, rules string
		mutate              func(*doctorRuntime)
		wantFailure         bool
		want                string
	}{
		{"unavailable", "", "", func(rt *doctorRuntime) { rt.lookPath = func(string) (string, error) { return "", os.ErrNotExist } }, false, "SKIP ufw: command unavailable"},
		{"inactive", "Status: inactive", "", nil, false, "SKIP ufw: inactive"},
		{"all", "Status: active", activeRules, nil, false, "PASS ufw-forward"},
		{"missing-dns-udp", "Status: active", activeRules[72:], nil, true, "FAIL ufw-dns-udp"},
		{"missing-dns-tcp", "Status: active", "ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'\n" + "ufw route allow in on masque0 out on eth0 from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'", nil, true, "FAIL ufw-dns-tcp"},
		{"missing-forward", "Status: active", "ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'\nufw allow in on masque0 to 10.200.0.1 port 5353 proto tcp comment 'jiejie-masque-connect-ip-dns'", nil, true, "FAIL ufw-forward"},
		{"runner-error", "Status: active", "", func(rt *doctorRuntime) {
			rt.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("boom") }
		}, false, "WARN ufw: status query failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := doctorTestRuntime(t, tc.status, tc.rules)
			if tc.mutate != nil {
				tc.mutate(rt)
			}
			var out bytes.Buffer
			if got := runDoctor(&out, c, *rt); got != tc.wantFailure {
				t.Fatalf("failure = %t, want %t; %s", got, tc.wantFailure, out.String())
			}
			if !bytes.Contains(out.Bytes(), []byte(tc.want)) {
				t.Fatalf("output missing %q: %s", tc.want, out.String())
			}
		})
	}
}

func TestDoctorUFWDisabledDNSAndStaleRule(t *testing.T) {
	dns := false
	c := doctorTestConfig(dns)
	stale := "ufw allow in on oldtun to 10.200.0.1 port 5353 proto udp comment 'jiejie-masque-connect-ip-dns'\n" +
		"ufw route allow in on masque0 out on oldeth from 10.200.0.0/16 comment 'jiejie-masque-connect-ip-forward'\n"
	rt, _ := doctorTestRuntime(t, "Status: active", stale)
	var out bytes.Buffer
	if !runDoctor(&out, c, *rt) {
		t.Fatalf("stale rules must not satisfy contract: %s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("SKIP ufw-dns: DNS gateway disabled")) {
		t.Fatalf("DNS disabled output: %s", out.String())
	}
}
