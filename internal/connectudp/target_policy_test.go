package connectudp

import (
	"context"
	"testing"
)

func TestTargetPolicyRejectsPrivateAndLocalAddresses(t *testing.T) {
	p := TargetPolicy{}
	for _, target := range []string{"127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443", "[fe80::1]:443", "[fd00::1]:443", "224.0.0.1:443", "0.0.0.0:443"} {
		if _, err := p.ResolveTarget(context.Background(), "tcp", target); err == nil {
			t.Fatalf("allowed %s", target)
		}
	}
}

func TestTargetPolicyAllowsExplicitPrivateAndPublic(t *testing.T) {
	if got, err := (TargetPolicy{AllowPrivate: true}).ResolveTarget(context.Background(), "tcp", "127.0.0.1:443"); err != nil || got != "127.0.0.1:443" {
		t.Fatalf("explicit private = %q, %v", got, err)
	}
	if got, err := (TargetPolicy{}).ResolveTarget(context.Background(), "udp", "1.1.1.1:53"); err != nil || got != "1.1.1.1:53" {
		t.Fatalf("public = %q, %v", got, err)
	}
}
