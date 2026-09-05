package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCleanupConntrackRejectsNonIPv4(t *testing.T) {
	if err := CleanupConntrack(netip.MustParseAddr("::1")); err == nil {
		t.Fatal("expected IPv6 rejection")
	}
}

func TestCleanupConntrackRejectsNonIPv4WithoutRunningCommand(t *testing.T) {
	called := false
	runner := func(context.Context, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	if err := cleanupConntrackWithOptions(netip.MustParseAddr("::1"), time.Second, runner); err == nil {
		t.Fatal("expected IPv6 rejection")
	}
	if called {
		t.Fatal("conntrack runner called for non-IPv4 address")
	}
}

func TestCleanupConntrackNoMatchContinuesBothDirections(t *testing.T) {
	tests := []struct {
		name string
		out  string
	}{
		{name: "plural", out: "0 flow entries have been deleted.\n"},
		{name: "singular", out: "0 flow entry has been deleted.\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			runner := func(_ context.Context, args ...string) ([]byte, error) {
				calls = append(calls, strings.Join(args, " "))
				return []byte(tt.out), errors.New("exit status 1")
			}
			if err := cleanupConntrackWithOptions(netip.MustParseAddr("10.0.0.1"), time.Second, runner); err != nil {
				t.Fatalf("cleanup returned error: %v", err)
			}
			want := []string{"-D -s 10.0.0.1", "-D -d 10.0.0.1"}
			if strings.Join(calls, "|") != strings.Join(want, "|") {
				t.Fatalf("calls=%v, want %v", calls, want)
			}
		})
	}
}

func TestCleanupConntrackDirectionOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		firstErr  error
		firstOut  string
		secondErr error
		secondOut string
		wantErr   bool
		wantCalls int
	}{
		{name: "both success", wantCalls: 2},
		{name: "source no-match destination success", firstOut: "0 flow entries have been deleted.", firstErr: errors.New("exit status 1"), wantCalls: 2},
		{name: "source success destination no-match", secondOut: "0 flow entry has been deleted.", secondErr: errors.New("exit status 1"), wantCalls: 2},
		{name: "real failure stops", firstOut: "Operation not permitted", firstErr: errors.New("exit status 1"), wantErr: true, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			runner := func(_ context.Context, _ ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte(tt.firstOut), tt.firstErr
				}
				return []byte(tt.secondOut), tt.secondErr
			}
			err := cleanupConntrackWithOptions(netip.MustParseAddr("10.0.0.1"), time.Second, runner)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Fatalf("calls=%d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestCleanupConntrackCancelAfterNoMatchIsNotTimeout(t *testing.T) {
	runner := func(context.Context, ...string) ([]byte, error) {
		return []byte("0 flow entries have been deleted."), errors.New("exit status 1")
	}
	if err := cleanupConntrackWithOptions(netip.MustParseAddr("10.0.0.1"), time.Second, runner); err != nil {
		t.Fatalf("cleanup returned error after command cancellation: %v", err)
	}
}

func TestCleanupConntrackTimeout(t *testing.T) {
	runner := func(ctx context.Context, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	err := cleanupConntrackWithOptions(netip.MustParseAddr("10.0.0.1"), 5*time.Millisecond, runner)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("error=%v, want timeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want context.DeadlineExceeded", err)
	}
}
