package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectudp"
)

func TestCanonicalExampleConfigsUseCurrentSemanticValidators(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))

	connectIPPath := filepath.Join(root, "configs", "connect-ip.example.yaml")
	connectIP, err := config.Load(connectIPPath)
	if err != nil {
		t.Fatalf("connect-ip example rejected: %v", err)
	}
	if connectIP.Mode != "connect-ip" {
		t.Fatalf("connect-ip example mode = %q", connectIP.Mode)
	}

	connectUDPPath := filepath.Join(root, "configs", "connect-udp.example.yaml")
	connectUDP, err := connectudp.Load(connectUDPPath)
	if err != nil {
		t.Fatalf("connect-udp example rejected: %v", err)
	}
	if connectUDP.Mode != "connect-udp" {
		t.Fatalf("connect-udp example mode = %q", connectUDP.Mode)
	}
}
