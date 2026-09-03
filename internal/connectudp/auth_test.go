package connectudp

import (
	"encoding/base64"
	mh "github.com/metacubex/http"
	"testing"
)

func TestCredentialsFallback(t *testing.T) {
	r := &mh.Request{}
	r.Header = make(map[string][]string)
	r.Header.Set("Authorization", "not-basic")
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("u:p")))
	u, p, ok := credentials(r)
	if !ok || u != "u" || p != "p" {
		t.Fatalf("fallback failed: %q %q %v", u, p, ok)
	}
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong:x")))
	u, p, ok = credentials(r)
	if !ok || u != "wrong" || p != "x" {
		t.Fatal("valid Authorization should take precedence")
	}
}
