package connectudp

import (
	"os"
	"testing"
	"time"
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

func TestTargetPolicyConnectTimeoutDefaultsAndValidation(t *testing.T) {
	c := Config{Mode: "connect-udp", Listen: "127.0.0.1:4433", PublicAuthority: "proxy.test"}
	c.TLS.Cert, c.TLS.Key = "cert", "key"
	c.QUIC.StatelessResetKeyFile = "/tmp/reset.key"
	c.Auth.AllowUnauthenticated = true
	if err := c.Validate(false); err != nil {
		t.Fatal(err)
	}
	if got := c.TargetPolicy.ConnectTimeoutDuration(); got != 10*time.Second {
		t.Fatalf("default connect timeout = %s", got)
	}
	for _, value := range []string{"0s", "-1s", "not-a-duration"} {
		c.TargetPolicy.ConnectTimeout = value
		if err := c.Validate(false); err == nil {
			t.Fatalf("connect_timeout %q was accepted", value)
		}
	}
	for _, value := range []string{"1s", "10s", "30s"} {
		c.TargetPolicy.ConnectTimeout = value
		if err := c.Validate(false); err != nil {
			t.Fatalf("connect_timeout %q rejected: %v", value, err)
		}
	}
}

func validMultiUserConfig(users ...AuthUser) Config {
	c := Config{Mode: "connect-udp", Listen: "127.0.0.1:4433", PublicAuthority: "proxy.test"}
	c.TLS.Cert, c.TLS.Key = "cert", "key"
	c.QUIC.StatelessResetKeyFile = "/tmp/reset.key"
	c.Auth.Users = users
	return c
}

func TestValidateRequiresUniqueEffectiveAuthIdentities(t *testing.T) {
	tests := []struct {
		name  string
		users []AuthUser
		valid bool
	}{
		{
			name:  "duplicate explicit names",
			users: []AuthUser{{Name: "iphone", Username: "user-a"}, {Name: "iphone", Username: "user-b"}},
		},
		{
			name:  "fallback and explicit collision",
			users: []AuthUser{{Username: "user-a"}, {Name: "user-a", Username: "user-b"}},
		},
		{
			name:  "two unnamed users",
			users: []AuthUser{{Username: "user-a"}, {Username: "user-b"}},
			valid: true,
		},
		{
			name:  "explicit name equal to own username",
			users: []AuthUser{{Name: "iphone", Username: "iphone"}},
			valid: true,
		},
		{
			name:  "duplicate usernames",
			users: []AuthUser{{Username: "same"}, {Username: "same"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validMultiUserConfig(tt.users...).Validate(false)
			if tt.valid && err != nil {
				t.Fatalf("valid users rejected: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("identity collision was accepted")
			}
		})
	}
}

func TestResolveCredentialsUsesEffectiveAuthIdentity(t *testing.T) {
	t.Setenv("MASQUE_TEST_PASSWORD", "env-secret")
	c := validMultiUserConfig(
		AuthUser{Username: "user-a", Password: "a"},
		AuthUser{Name: "tablet", Username: "user-b", Password: "b"},
		AuthUser{Username: "user-c", PasswordEnv: "MASQUE_TEST_PASSWORD"},
	)
	creds, err := c.ResolveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds["user-a"].Name != "user-a" || creds["user-b"].Name != "tablet" || creds["user-c"].Password != "env-secret" {
		t.Fatalf("credential identities = %#v", creds)
	}
	if got := effectiveAuthUserName(c.Auth.Users[0]); got != creds["user-a"].Name {
		t.Fatalf("fallback identity = %q, credential name = %q", got, creds["user-a"].Name)
	}
}
