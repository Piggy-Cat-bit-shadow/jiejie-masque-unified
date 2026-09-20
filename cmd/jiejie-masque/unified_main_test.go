package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnoseReportCommand(t *testing.T) {
	if err := diagnoseReportCommand([]string{"diagnose-report"}); err == nil {
		t.Fatal("missing report path should be rejected")
	}
	path := filepath.Join(t.TempDir(), "pipeline.jsonl")
	line := `Jul 19 12:00:00 host jiejie-masque[1]: CONNECT-IP pipeline: {"interval_seconds":1,"stages":{}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := diagnoseReportCommand([]string{"diagnose-report", path}); err != nil {
		t.Fatalf("journal-prefixed report rejected: %v", err)
	}
}
