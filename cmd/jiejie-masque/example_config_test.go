package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

func TestCanonicalExampleConfigsUseCurrentSemanticValidators(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))

	connectIPPath := filepath.Join(root, "configs", "connect-ip.example.yaml")
	_, err := config.Load(connectIPPath)
	if err != nil {
		t.Fatalf("connect-ip example rejected: %v", err)
	}
}
