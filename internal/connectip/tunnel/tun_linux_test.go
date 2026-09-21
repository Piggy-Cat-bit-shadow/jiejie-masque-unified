//go:build linux

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfigureIPv6AddressUsesNODADAndDeadline(t *testing.T) {
	want := []string{"-6", "addr", "replace", "fd00:200::1/64", "dev", "masque0", "nodad"}
	called := false
	err := configureIPv6AddressWithRunner("masque0", netip.MustParsePrefix("fd00:200::1/64"), func(ctx context.Context, command string, args ...string) ([]byte, error) {
		called = true
		if command != "ip" || !reflect.DeepEqual(args, want) {
			t.Fatalf("command = %s %v", command, args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("IPv6 address command has no deadline")
		}
		return nil, nil
	})
	if err != nil || !called {
		t.Fatalf("configure IPv6 address = %v, called=%t", err, called)
	}
}

func TestConfigureIPv6AddressReportsCommandFailure(t *testing.T) {
	err := configureIPv6AddressWithRunner("masque0", netip.MustParsePrefix("fd00:200::1/64"), func(context.Context, string, ...string) ([]byte, error) {
		return []byte("operation not permitted"), errors.New("exit status 2")
	})
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("error = %v", err)
	}
}

func TestConfigureIPv6AddressReportsTimeout(t *testing.T) {
	err := configureIPv6AddressWithRunner("masque0", netip.MustParsePrefix("fd00:200::1/64"), func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("missing context deadline")
		}
		if time.Until(deadline) > 2*time.Second {
			t.Fatal("timeout exceeds two seconds")
		}
		return nil, context.DeadlineExceeded
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v", err)
	}
}
