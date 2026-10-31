// Package httpx contains HTTP middleware used to harden the server.
package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ctxKey int

const (
	ctxClientIP ctxKey = iota
	ctxCSPNonce
)

// ClientIP returns the client IP resolved by RealIP.
func ClientIP(r *http.Request) string {
	if v, ok := r.Context().Value(ctxClientIP).(string); ok {
		return v
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// Chain applies middlewares in order (first is outermost).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Recover converts panics into 500 responses and logs them.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
						panic(rec)
					}
					log.Error("panic", "err", rec, "stack", string(debug.Stack()), "path", r.URL.Path)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RealIP resolves the client IP. The CF-Connecting-IP header (or the last
// X-Forwarded-For hop) is trusted only when the direct peer is a trusted
// proxy. When requireProxy is set, connections not from a trusted proxy are
// rejected outright so Cloudflare cannot be bypassed by hitting the origin.
func RealIP(trusted []*net.IPNet, requireProxy bool) func(http.Handler) http.Handler {
	isTrusted := func(ip net.IP) bool {
		for _, n := range trusted {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			peer := net.ParseIP(host)
			ip := host
			fromProxy := peer != nil && isTrusted(peer)
			if requireProxy && !fromProxy {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if fromProxy {
				cand := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
				if cand == "" {
					if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
						parts := strings.Split(xff, ",")
						cand = strings.TrimSpace(parts[len(parts)-1])
					}
				}
				if p := net.ParseIP(cand); p != nil {
					ip = p.String()
				}
			}
			ctx := context.WithValue(r.Context(), ctxClientIP, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SecurityHeaders sets a strict set of browser hardening headers.
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cache-Control", "no-store")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OriginCheck rejects state-changing requests that do not provably come
// from our own origin. Browsers set Sec-Fetch-Site themselves (pages cannot
// forge it), so "same-origin" is accepted outright; otherwise the Origin
// header (or Referer as a fallback) must match the configured origin.
// Together with SameSite=Strict cookies this defeats CSRF without tokens.
// Note: Referrer-Policy must not be "no-referrer", or Chrome sends
// "Origin: null" on same-origin form posts.
func OriginCheck(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			switch r.Header.Get("Sec-Fetch-Site") {
			case "same-origin":
				next.ServeHTTP(w, r)
				return
			case "", "none":
				// fall through to Origin/Referer check
			default:
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
			o := r.Header.Get("Origin")
			if o == "" {
				if ref := r.Header.Get("Referer"); ref != "" {
					if u, err := url.Parse(ref); err == nil {
						o = u.Scheme + "://" + u.Host
					}
				}
			}
			if o == "" || !strings.EqualFold(o, origin) {
				http.Error(w, "origin check failed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody caps request bodies.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Limiter is a per-client-IP token bucket rate limiter.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*entry
	r       rate.Limit
	b       int
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewLimiter allows r events/second with bursts of b per IP.
func NewLimiter(r rate.Limit, b int) *Limiter {
	l := &Limiter{buckets: map[string]*entry{}, r: r, b: b}
	go l.gc()
	return l
}

func (l *Limiter) gc() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		for k, e := range l.buckets {
			if time.Since(e.seen) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// Allow reports whether key may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.r, l.b)}
		l.buckets[key] = e
	}
	e.seen = time.Now()
	return e.lim.Allow()
}

// Middleware returns 429 when the client IP exceeds the limit.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(ClientIP(r)) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Logging emits one structured line per request.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"ip", ClientIP(r),
				"dur_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
