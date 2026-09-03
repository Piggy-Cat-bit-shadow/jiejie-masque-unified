package connectudp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/quic-go"
	metatls "github.com/metacubex/tls"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode            string `yaml:"mode"`
	Listen          string `yaml:"listen"`
	PublicAuthority string `yaml:"public_authority"`
	TLS             struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	Auth   AuthConfig `yaml:"auth"`
	Limits struct {
		MaxActiveFlows        int    `yaml:"max_active_flows"`
		MaxActiveFlowsPerUser int    `yaml:"max_active_flows_per_user"`
		FlowIdleTimeout       string `yaml:"flow_idle_timeout"`
	} `yaml:"limits"`
	QUIC struct {
		KeepAlivePeriod       string `yaml:"keep_alive_period"`
		MaxIdleTimeout        string `yaml:"max_idle_timeout"`
		StatelessResetKeyFile string `yaml:"stateless_reset_key_file"`
	} `yaml:"quic"`
}

type AuthUser struct {
	Name        string `yaml:"name,omitempty"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password,omitempty"`
	PasswordEnv string `yaml:"password_env,omitempty"`
}
type AuthConfig struct {
	Username             string     `yaml:"username"`
	Password             string     `yaml:"password"`
	UsernameEnv          string     `yaml:"username_env"`
	PasswordEnv          string     `yaml:"password_env"`
	AllowUnauthenticated bool       `yaml:"allow_unauthenticated"`
	Users                []AuthUser `yaml:"users,omitempty"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if e = dec.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		if e == nil {
			e = fmt.Errorf("multiple YAML documents are not allowed")
		}
		return c, e
	}
	return c, c.Validate(false)
}
func (c Config) Validate(checkFiles bool) error {
	if c.Mode != "connect-udp" {
		return fmt.Errorf("mode must be connect-udp")
	}
	if _, e := net.ResolveUDPAddr("udp", c.Listen); e != nil {
		return fmt.Errorf("invalid listen: %w", e)
	}
	if c.PublicAuthority == "" || c.PublicAuthority != urlAuthority(c.PublicAuthority) {
		return fmt.Errorf("invalid public_authority")
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("tls cert and key are required")
	}
	if (c.Auth.Username == "") != (c.Auth.Password == "") || (c.Auth.UsernameEnv == "") != (c.Auth.PasswordEnv == "") {
		return fmt.Errorf("auth credentials and env names must be paired")
	}
	if len(c.Auth.Users) > 0 && (c.Auth.Username != "" || c.Auth.Password != "" || c.Auth.UsernameEnv != "" || c.Auth.PasswordEnv != "") {
		return fmt.Errorf("auth users cannot be combined with legacy credentials")
	}
	seen := map[string]bool{}
	for _, u := range c.Auth.Users {
		if u.Username == "" || seen[u.Username] {
			return fmt.Errorf("auth usernames must be unique and non-empty")
		}
		seen[u.Username] = true
		if u.Password != "" && u.PasswordEnv != "" {
			return fmt.Errorf("user %s sets both password and password_env", u.Username)
		}
	}
	if c.Limits.MaxActiveFlows == 0 {
		c.Limits.MaxActiveFlows = 256
	}
	if c.Limits.MaxActiveFlowsPerUser == 0 {
		c.Limits.MaxActiveFlowsPerUser = 64
	}
	if c.Limits.FlowIdleTimeout == "" {
		c.Limits.FlowIdleTimeout = "1h"
	}
	if c.Limits.MaxActiveFlows < 1 || c.Limits.MaxActiveFlows > 4096 || c.Limits.MaxActiveFlowsPerUser < 1 || c.Limits.MaxActiveFlowsPerUser > c.Limits.MaxActiveFlows {
		return fmt.Errorf("invalid flow limits")
	}
	if d, e := time.ParseDuration(c.Limits.FlowIdleTimeout); e != nil || d <= 0 {
		return fmt.Errorf("invalid flow_idle_timeout")
	}
	kp := c.QUIC.KeepAlivePeriod
	if kp == "" {
		kp = "15s"
	}
	idle := c.QUIC.MaxIdleTimeout
	if idle == "" {
		idle = "2m"
	}
	for _, v := range []string{kp, idle} {
		d, e := time.ParseDuration(v)
		if e != nil || d <= 0 {
			return fmt.Errorf("invalid QUIC duration")
		}
	}
	if c.QUIC.StatelessResetKeyFile == "" {
		return fmt.Errorf("stateless reset key path is required")
	}
	if checkFiles {
		if _, e := metatls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key); e != nil {
			return e
		}
		if st, e := os.Stat(c.QUIC.StatelessResetKeyFile); e == nil {
			if st.Size() != int64(len(quic.StatelessResetKey{})) {
				return fmt.Errorf("invalid stateless reset key length")
			}
		} else if !os.IsNotExist(e) {
			return fmt.Errorf("stateless reset key: %w", e)
		}
		_ = filepath.Clean(c.QUIC.StatelessResetKeyFile)
	}
	return nil
}

func (c Config) KeepAlive() time.Duration {
	d, _ := time.ParseDuration(c.QUIC.KeepAlivePeriod)
	if d == 0 {
		d = 15 * time.Second
	}
	return d
}
func (c Config) IdleTimeout() time.Duration {
	d, _ := time.ParseDuration(c.QUIC.MaxIdleTimeout)
	if d == 0 {
		d = 2 * time.Minute
	}
	return d
}
func (c Config) FlowIdleTimeout() time.Duration {
	d, _ := time.ParseDuration(c.Limits.FlowIdleTimeout)
	if d == 0 {
		d = time.Hour
	}
	return d
}
func (c Config) ResolveAuth() (string, string, error) {
	if (c.Auth.Username == "") != (c.Auth.Password == "") {
		return "", "", fmt.Errorf("auth username and password must be paired")
	}
	if c.Auth.Username != "" {
		return c.Auth.Username, c.Auth.Password, nil
	}
	if len(c.Auth.Users) > 0 {
		return "", "", nil
	}
	if c.Auth.UsernameEnv == "" {
		if c.Auth.AllowUnauthenticated {
			return "", "", nil
		}
		return "", "", fmt.Errorf("CONNECT-UDP authentication is required; set credentials/users or explicitly allow unauthenticated mode")
	}
	u, uok := os.LookupEnv(c.Auth.UsernameEnv)
	p, pok := os.LookupEnv(c.Auth.PasswordEnv)
	if !uok || !pok || u == "" || p == "" {
		return "", "", fmt.Errorf("configured auth environment values must both exist and be non-empty")
	}
	return u, p, nil
}

type Credential struct {
	Name     string
	Password string
}

func (c Config) ResolveCredentials() (map[string]Credential, error) {
	if len(c.Auth.Users) == 0 {
		u, p, e := c.ResolveAuth()
		if e != nil {
			return nil, e
		}
		if u == "" {
			return nil, nil
		}
		return map[string]Credential{u: {Name: u, Password: p}}, nil
	}
	result := make(map[string]Credential, len(c.Auth.Users))
	for _, user := range c.Auth.Users {
		name := user.Name
		if name == "" {
			name = user.Username
		}
		pass := user.Password
		if user.PasswordEnv != "" {
			var ok bool
			pass, ok = os.LookupEnv(user.PasswordEnv)
			if !ok || pass == "" {
				return nil, fmt.Errorf("configured password_env for user %s is missing or empty", user.Username)
			}
		}
		if pass == "" {
			return nil, fmt.Errorf("password required for user %s", user.Username)
		}
		result[user.Username] = Credential{Name: name, Password: pass}
	}
	return result, nil
}
func urlAuthority(s string) string {
	u, e := url.Parse("https://" + s)
	if e != nil || u.Host != s || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return s
}
