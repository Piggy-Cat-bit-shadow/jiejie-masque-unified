package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const networkPrepareTestKey = "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="

func writeNetworkPrepareConfig(t *testing.T, tunnelIPv4 string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test config.yaml")
	content := "mode: connect-ip\n" +
		"listen: 127.0.0.1:4434\n" +
		"tls:\n  cert: c\n  key: k\n" +
		"client:\n  public_keys: [" + networkPrepareTestKey + "]\n  tunnel_ipv4: 10.200.0.2/32\n" +
		"server:\n  tunnel_ipv4: " + tunnelIPv4 + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNetworkPrepareInfoUsesConfigParserForQuotedCIDR(t *testing.T) {
	path := writeNetworkPrepareConfig(t, `"10.200.0.1/16"`)
	var output bytes.Buffer
	if err := networkPrepareInfo(&output, path, ""); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "10.200.0.1/16\n" {
		t.Fatalf("normalized tunnel prefix = %q", got)
	}
}

func TestNetworkPrepareInfoAcceptsSingleQuotedCIDRWithComment(t *testing.T) {
	path := writeNetworkPrepareConfig(t, `'10.200.0.1/16' # tunnel network`)
	var output bytes.Buffer
	if err := networkPrepareInfo(&output, path, "tunnel-prefix"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "10.200.0.1/16\n" {
		t.Fatalf("normalized tunnel prefix = %q", got)
	}
}

func TestNetworkPrepareInfoRejectsConfigParserErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(string) string
	}{
		{name: "unknown field", mutate: func(config string) string { return config + "unknown_field: true\n" }},
		{name: "invalid prefix", mutate: func(config string) string { return strings.Replace(config, "10.200.0.1/16", "not-a-prefix", 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			base := "mode: connect-ip\nlisten: 127.0.0.1:4434\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + networkPrepareTestKey + "]\n  tunnel_ipv4: 10.200.0.2/32\nserver:\n  tunnel_ipv4: 10.200.0.1/16\n"
			if err := os.WriteFile(path, []byte(tc.mutate(base)), 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := networkPrepareInfo(&output, path, ""); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestNetworkPrepareInfoExternalInterface(t *testing.T) {
	path := writeNetworkPrepareConfig(t, "10.200.0.1/16")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, []byte("host_network:\n  external_interface: eth1\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := networkPrepareInfo(&output, path, "external-interface"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "eth1\n" {
		t.Fatalf("external interface = %q", got)
	}
}

func TestNetworkPrepareInfoExternalInterfaceOmitted(t *testing.T) {
	path := writeNetworkPrepareConfig(t, "10.200.0.1/16")
	var output bytes.Buffer
	if err := networkPrepareInfo(&output, path, "external-interface"); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("omitted external interface output = %q", output.String())
	}
}

func TestNetworkPrepareInfoRejectsUnsupportedField(t *testing.T) {
	path := writeNetworkPrepareConfig(t, "10.200.0.1/16")
	var output bytes.Buffer
	if err := networkPrepareInfo(&output, path, "password"); err == nil {
		t.Fatal("unsupported field was accepted")
	}
}
