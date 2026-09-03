package connectudp

import (
	"crypto/subtle"
	"encoding/base64"
	mh "github.com/metacubex/http"
	"strings"
)

func credentials(r *mh.Request) (string, string, bool) {
	for _, v := range []string{r.Header.Get("Authorization"), r.Header.Get("Proxy-Authorization")} {
		if v == "" || !strings.HasPrefix(strings.ToLower(v), "basic ") {
			continue
		}
		b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
		if e != nil {
			continue
		}
		p := strings.IndexByte(string(b), ':')
		if p < 0 {
			continue
		}
		return string(b[:p]), string(b[p+1:]), true
	}
	return "", "", false
}
func WithAuth(next mh.Handler, u, p string) mh.Handler {
	return mh.HandlerFunc(func(w mh.ResponseWriter, r *mh.Request) {
		if u != "" || p != "" {
			a, b, ok := credentials(r)
			if !ok || subtle.ConstantTimeCompare([]byte(a), []byte(u)) != 1 || subtle.ConstantTimeCompare([]byte(b), []byte(p)) != 1 {
				w.Header().Set("Proxy-Authenticate", `Basic realm="masque"`)
				w.WriteHeader(407)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
