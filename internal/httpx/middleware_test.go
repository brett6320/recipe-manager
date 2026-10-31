package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRealIP(t *testing.T) {
	_, cf, _ := net.ParseCIDR("103.21.244.0/22")
	h := RealIP([]*net.IPNet{cf}, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(ClientIP(r)))
	}))

	cases := []struct{ remote, cfip, want string }{
		{"103.21.244.9:1234", "203.0.113.5", "203.0.113.5"},  // trusted proxy, header honoured
		{"198.51.100.7:1234", "203.0.113.5", "198.51.100.7"}, // untrusted peer, header ignored
		{"103.21.244.9:1234", "", "103.21.244.9"},            // proxy without header
	}
	for _, c := range cases {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.cfip != "" {
			r.Header.Set("CF-Connecting-IP", c.cfip)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Body.String(); got != c.want {
			t.Errorf("remote=%s cf=%s: got %s want %s", c.remote, c.cfip, got, c.want)
		}
	}
}

func TestRealIPRequireProxy(t *testing.T) {
	_, cf, _ := net.ParseCIDR("103.21.244.0/22")
	h := RealIP([]*net.IPNet{cf}, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestOriginCheck(t *testing.T) {
	h := OriginCheck("https://recipes.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cases := []struct {
		method, origin, sfs string
		want                int
	}{
		{"GET", "", "cross-site", 200},
		{"POST", "https://recipes.example.com", "same-origin", 200},
		{"POST", "https://evil.example", "", 403},
		{"POST", "", "", 403},
		{"POST", "https://recipes.example.com", "cross-site", 403},
		{"POST", "null", "same-origin", 200}, // Chrome with strict referrer policy
		{"POST", "null", "", 403},
		{"POST", "null", "none", 403},
	}
	for _, c := range cases {
		r := httptest.NewRequestWithContext(context.Background(), c.method, "/x", strings.NewReader(""))
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.sfs != "" {
			r.Header.Set("Sec-Fetch-Site", c.sfs)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s origin=%q sfs=%q: got %d want %d", c.method, c.origin, c.sfs, w.Code, c.want)
		}
	}
}
