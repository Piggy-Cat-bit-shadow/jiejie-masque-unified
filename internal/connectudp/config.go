package connectudp

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

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
	Auth struct {
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		UsernameEnv string `yaml:"username_env"`
		PasswordEnv string `yaml:"password_env"`
	} `yaml:"auth"`
	QUIC struct {
		KeepAlivePeriod       string `yaml:"keep_alive_period"`
		MaxIdleTimeout        string `yaml:"max_idle_timeout"`
		StatelessResetKeyFile string `yaml:"stateless_reset_key_file"`
	} `yaml:"quic"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	if e = yaml.Unmarshal(b, &c); e != nil {
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
		if st, e := os.Stat(c.QUIC.StatelessResetKeyFile); e == nil && st.Size() != 16 {
			return fmt.Errorf("invalid stateless reset key length")
		}
		_ = filepath.Clean(c.QUIC.StatelessResetKeyFile)
	}
	return nil
}
func urlAuthority(s string) string {
	u, e := url.Parse("https://" + s)
	if e != nil || u.Host != s || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return s
}
