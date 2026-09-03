package connectudp

import (
	mh "github.com/metacubex/http"
	"github.com/yosida95/uritemplate/v3"
	"net/url"
	"testing"
)

func TestParseProxyRequestStatuses(t *testing.T) {
	tmpl, _ := uritemplate.New("https://proxy.test/.well-known/masque/udp/{target_host}/{target_port}/")
	request := func(path string) *mh.Request {
		return &mh.Request{Method: "CONNECT", Proto: "connect-udp", Host: "proxy.test", URL: &url.URL{Scheme: "https", Host: "proxy.test", Path: path}}
	}
	good := request("/.well-known/masque/udp/example.com/443/")
	got, e := ParseProxyRequest(good, tmpl)
	if e != nil || got.Target != "example.com:443" {
		t.Fatalf("hostname: %#v %v", got, e)
	}
	for _, tc := range []struct {
		name string
		r    *mh.Request
		code int
	}{
		{"method", func() *mh.Request { r := request(good.URL.Path); r.Method = "GET"; return r }(), 405},
		{"protocol", func() *mh.Request { r := request(good.URL.Path); r.Proto = "h2"; return r }(), 501},
		{"authority", func() *mh.Request { r := request(good.URL.Path); r.Host = "other.test"; return r }(), 400},
		{"missing host", request("/.well-known/masque/udp//443/"), 400},
		{"bad port", request("/.well-known/masque/udp/example.com/nope/"), 400},
	} {
		_, e := ParseProxyRequest(tc.r, tmpl)
		if e == nil || e.(*ProxyRequestParseError).HTTPStatus != tc.code {
			t.Errorf("%s: %v", tc.name, e)
		}
	}
}
