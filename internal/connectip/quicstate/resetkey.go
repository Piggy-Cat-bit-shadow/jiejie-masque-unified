package quicstate

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/metacubex/quic-go"
)

const ResetKeySize = len(quic.StatelessResetKey{})

func ValidatePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("stateless reset key path must be absolute and clean")
	}
	return nil
}

func LoadOrCreate(path string) (quic.StatelessResetKey, error) {
	var key quic.StatelessResetKey
	if err := ValidatePath(path); err != nil {
		return key, err
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != ResetKeySize {
			return key, fmt.Errorf("stateless reset key has length %d, want %d", len(b), ResetKeySize)
		}
		copy(key[:], b)
		return key, nil
	}
	if !os.IsNotExist(err) {
		return key, fmt.Errorf("read stateless reset key: %w", err)
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate stateless reset key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("create reset key directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return LoadOrCreate(path)
		}
		return key, fmt.Errorf("create stateless reset key: %w", err)
	}
	cleanup := func() { _ = f.Close(); _ = os.Remove(path) }
	n, err := f.Write(key[:])
	if err != nil || n != len(key) {
		cleanup()
		if err == nil {
			err = io.ErrShortWrite
		}
		return key, fmt.Errorf("write stateless reset key: %w", err)
	}
	if err = f.Sync(); err != nil {
		cleanup()
		return key, fmt.Errorf("sync stateless reset key: %w", err)
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return key, fmt.Errorf("close stateless reset key: %w", err)
	}
	confirmed, err := os.ReadFile(path)
	if err != nil || len(confirmed) != ResetKeySize || !bytes.Equal(confirmed, key[:]) {
		_ = os.Remove(path)
		return key, fmt.Errorf("confirm stateless reset key: %w", err)
	}
	copy(key[:], confirmed)
	return key, nil
}

func ValidateExisting(path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read stateless reset key: %w", err)
	}
	if len(b) != ResetKeySize {
		return fmt.Errorf("stateless reset key has length %d, want %d", len(b), ResetKeySize)
	}
	return nil
}
