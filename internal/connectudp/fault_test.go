package connectudp

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFaultStatusMappings(t *testing.T) {
	if got := statusForDialError(&net.AddrError{Err: "missing port"}); got != 400 {
		t.Fatalf("malformed target status=%d", got)
	}
	if got := statusForDialError(&net.OpError{Err: errors.New("connection refused")}); got != 502 {
		t.Fatalf("refused target status=%d", got)
	}
	if got := statusForDialError(context.DeadlineExceeded); got != 504 {
		t.Fatalf("TCP timeout target status=%d", got)
	}
	if got := errToStatus(&net.DNSError{IsNotFound: true}); got != 502 {
		t.Fatalf("dns target status=%d", got)
	}
	if got := errToStatus(context.DeadlineExceeded); got != 504 {
		t.Fatalf("timeout target status=%d", got)
	}
}

func TestMissingAuthEnvironmentFailsClosed(t *testing.T) {
	c := Config{}
	c.Auth.Users = []AuthUser{{Username: "test-user", PasswordEnv: "MASQUE_MISSING_TEST_SECRET"}}
	_ = os.Unsetenv("MASQUE_MISSING_TEST_SECRET")
	if _, err := c.ResolveCredentials(); err == nil {
		t.Fatal("missing auth environment was accepted")
	}
	_ = os.Setenv("MASQUE_MISSING_TEST_SECRET", "")
	defer os.Unsetenv("MASQUE_MISSING_TEST_SECRET")
	if _, err := c.ResolveCredentials(); err == nil {
		t.Fatal("empty auth environment was accepted")
	}
}

func TestStartupRejectsCertificateFailures(t *testing.T) {
	c := integrationConfig(t)
	c.QUIC.StatelessResetKeyFile = filepath.Join(t.TempDir(), "reset.key")
	for name, mutate := range map[string]func(*Config){
		"missing certificate": func(c *Config) { c.TLS.Cert = filepath.Join(t.TempDir(), "missing-cert.pem") },
		"missing key":         func(c *Config) { c.TLS.Key = filepath.Join(t.TempDir(), "missing-key.pem") },
		"malformed pem": func(c *Config) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bad.pem")
			_ = os.WriteFile(path, []byte("not pem"), 0o600)
			c.TLS.Cert = path
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := c
			mutate(&copy)
			ready := make(chan string, 1)
			if err := serveContextWithReaper(t.Context(), copy, ready, 10); err == nil {
				t.Fatal("startup unexpectedly succeeded")
			}
			select {
			case got := <-ready:
				t.Fatalf("ready signal before startup failure: %s", got)
			default:
			}
		})
	}
}
