package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
)

func TestValidateQLogDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "qlog")
	if err := validateQLogDirectory(config.QLog{Enabled: true, Directory: dir}); err != nil {
		t.Fatalf("validate writable qlog directory: %v", err)
	}
	if err := validateQLogDirectory(config.QLog{}); err != nil {
		t.Fatalf("disabled qlog should not validate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateQLogDirectory(config.QLog{Enabled: true, Directory: path}); err == nil {
		t.Fatal("qlog file path unexpectedly accepted as directory")
	}
}
