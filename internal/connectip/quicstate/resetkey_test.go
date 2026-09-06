package quicstate

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
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
	malformed := []byte("short")
	if err := os.WriteFile(path, malformed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("expected malformed key failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, malformed) {
		t.Fatalf("malformed key was changed: %q", got)
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

func TestLoadOrCreateWaitsForConcurrentIncompleteKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	created := make(chan struct{})
	allowWrite := make(chan struct{})
	incompleteRead := make(chan struct{})
	var incompleteReadOnce sync.Once

	oldAfterCreateHook := resetKeyAfterCreateHook
	oldIncompleteReadHook := resetKeyIncompleteReadHook
	resetKeyAfterCreateHook = func() {
		close(created)
		<-allowWrite
	}
	resetKeyIncompleteReadHook = func() {
		incompleteReadOnce.Do(func() { close(incompleteRead) })
	}
	t.Cleanup(func() {
		resetKeyAfterCreateHook = oldAfterCreateHook
		resetKeyIncompleteReadHook = oldIncompleteReadHook
	})

	type result struct {
		key [32]byte
		err error
	}
	creatorResult := make(chan result, 1)
	loaderResult := make(chan result, 1)
	go func() {
		key, err := LoadOrCreate(path)
		creatorResult <- result{key: [32]byte(key), err: err}
	}()
	<-created

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("incomplete key length = %d, want 0", len(b))
	}

	go func() {
		key, err := LoadOrCreate(path)
		loaderResult <- result{key: [32]byte(key), err: err}
	}()
	<-incompleteRead
	close(allowWrite)

	creator := <-creatorResult
	if creator.err != nil {
		t.Fatal(creator.err)
	}
	loader := <-loaderResult
	if loader.err != nil {
		t.Fatal(loader.err)
	}
	if creator.key != loader.key {
		t.Fatal("concurrent loader did not receive the creator's key")
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != ResetKeySize || !bytes.Equal(b, creator.key[:]) {
		t.Fatal("winner key was not preserved")
	}
}

func filepathDir(path string) string { return filepath.Dir(path) }
