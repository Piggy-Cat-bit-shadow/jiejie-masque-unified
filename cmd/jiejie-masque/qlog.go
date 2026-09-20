package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Piggy-Cat-bit-shadow/jiejie-masque-unified/internal/connectip/config"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/qlog"
	"github.com/metacubex/quic-go/qlogwriter"
)

func newQLogTracer(cfg config.QLog) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	if !cfg.Enabled {
		return nil
	}
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		if err := os.MkdirAll(cfg.Directory, 0o700); err != nil {
			log.Printf("qlog: create directory: %v", err)
			return nil
		}
		label := "server"
		if isClient {
			label = "client"
		}
		// The filename contains only the QUIC connection ID and perspective;
		// no client certificate, identity, target, or tunnel address is logged.
		path := filepath.Join(cfg.Directory, fmt.Sprintf("%s_%s.sqlog", connID, label))
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			log.Printf("qlog: create %s: %v", path, err)
			return nil
		}
		trace := qlogwriter.NewConnectionFileSeq(f, isClient, connID, []string{qlog.EventSchema})
		go trace.Run()
		return trace
	}
}

func validateQLogDirectory(cfg config.QLog) error {
	if !cfg.Enabled {
		return nil
	}
	if err := os.MkdirAll(cfg.Directory, 0o700); err != nil {
		return fmt.Errorf("create qlog directory: %w", err)
	}
	info, err := os.Stat(cfg.Directory)
	if err != nil {
		return fmt.Errorf("stat qlog directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("qlog path is not a directory")
	}
	test, err := os.CreateTemp(cfg.Directory, ".write-test-*")
	if err != nil {
		return fmt.Errorf("qlog directory is not writable: %w", err)
	}
	name := test.Name()
	if err := test.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close qlog write test: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove qlog write test: %w", err)
	}
	return nil
}
