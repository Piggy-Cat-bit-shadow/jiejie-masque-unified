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

func TestCredentialsIdentityIsolatesAdmissionBuckets(t *testing.T) {
	c := validMultiUserConfig(
		AuthUser{Name: "phone", Username: "user-a", Password: "a"},
		AuthUser{Name: "tablet", Username: "user-b", Password: "b"},
	)
	creds, err := c.ResolveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	admission := NewAdmission(2, 1)
	var identities []string
	var releases []func()
	next := mh.HandlerFunc(func(_ mh.ResponseWriter, r *mh.Request) {
		identity := Identity(r)
		release, acquireErr := admission.Acquire(identity)
		if acquireErr != nil {
			t.Errorf("acquire %q: %v", identity, acquireErr)
			return
		}
		identities = append(identities, identity)
		releases = append(releases, release)
	})
	handler := WithCredentials(next, creds)
	for _, pair := range []string{"user-a:a", "user-b:b"} {
		r := &mh.Request{Header: make(map[string][]string)}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pair)))
		handler.ServeHTTP(nil, r)
	}
	for _, release := range releases {
		release()
	}
	if len(identities) != 2 || identities[0] != "phone" || identities[1] != "tablet" {
		t.Fatalf("authenticated identities = %v", identities)
	}
	if total, byUser := admission.Counts(); total != 0 || len(byUser) != 0 {
		t.Fatalf("admission not fully released: total=%d users=%v", total, byUser)
	}
}
