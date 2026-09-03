package quicstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "reset.key")
	if err := os.Mkdir(filepathDir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("key changed across reload")
	}
}

func TestLoadOrCreateRejectsMalformedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("expected malformed key failure")
	}
}

func TestValidateExistingDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.key")
	if err := ValidateExisting(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("check created a key")
	}
}

func TestLoadOrCreateDoesNotOverwriteConcurrentWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	results := make(chan [32]byte, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			key, err := LoadOrCreate(path)
			results <- [32]byte(key)
			errs <- err
		}()
	}
	var key [32]byte
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		got := <-results
		if i > 0 && got != key {
			t.Fatal("concurrent loaders got different keys")
		}
		key = got
	}
}

func filepathDir(path string) string { return filepath.Dir(path) }
