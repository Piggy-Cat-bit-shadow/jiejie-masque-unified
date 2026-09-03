package connectudp

import (
	"os"
	"testing"
)

func TestResolveAuth(t *testing.T) {
	c := Config{}
	c.Mode = "connect-udp"
	c.Auth.AllowUnauthenticated = true
	c.Auth.UsernameEnv = ""
	c.Auth.PasswordEnv = ""
	os.Unsetenv("TEST_MASQUE_U")
	os.Unsetenv("TEST_MASQUE_P")
	u, p, err := c.ResolveAuth()
	if err != nil || u != "" || p != "" {
		t.Fatalf("disabled auth: %q %q %v", u, p, err)
	}
	c.Auth.UsernameEnv = "TEST_MASQUE_U"
	c.Auth.PasswordEnv = "TEST_MASQUE_P"
	os.Setenv("TEST_MASQUE_U", "u")
	defer os.Unsetenv("TEST_MASQUE_U")
	if _, _, err := c.ResolveAuth(); err == nil {
		t.Fatal("expected one-sided env error")
	}
	os.Setenv("TEST_MASQUE_P", "p")
	defer os.Unsetenv("TEST_MASQUE_P")
	u, p, err = c.ResolveAuth()
	if err != nil || u != "u" || p != "p" {
		t.Fatalf("env auth: %q %q %v", u, p, err)
	}
	c.Auth.Username, c.Auth.Password = "explicit", "secret"
	u, p, err = c.ResolveAuth()
	if err != nil || u != "explicit" || p != "secret" {
		t.Fatal("explicit credentials must win")
	}
}

func TestValidateRejectsDisabledFlowIdleTimeout(t *testing.T) {
	c := Config{Mode: "connect-udp", Listen: "127.0.0.1:4433", PublicAuthority: "proxy.test"}
	c.TLS.Cert, c.TLS.Key = "cert", "key"
	c.QUIC.StatelessResetKeyFile = "/tmp/reset.key"
	c.Auth.AllowUnauthenticated = true
	c.Limits.FlowIdleTimeout = "0"
	if err := c.Validate(false); err == nil {
		t.Fatal("zero flow_idle_timeout must be rejected")
	}
}

func TestLoadRejectsUnknownFieldAndSecondDocument(t *testing.T) {
	base := "mode: connect-udp\nlisten: 127.0.0.1:4433\npublic_authority: proxy.test\ntls:\n  cert: cert\n  key: key\nauth:\n  allow_unauthenticated: true\nquic:\n  stateless_reset_key_file: /tmp/reset.key\n"
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(base+"unknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := os.WriteFile(path, []byte(base+"---\n"+base), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("second YAML document accepted")
	}
}
