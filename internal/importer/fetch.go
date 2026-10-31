// Package importer turns external recipe sources (URLs, HTML, JSON, PDF,
// plain text) into recipes.Recipe values. Nothing here is trusted: every
// string is sanitised and sizes are capped.
package importer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Fetcher downloads remote recipe pages with SSRF protection.
type Fetcher struct {
	client  *http.Client
	maxSize int64
}

// NewFetcher builds an HTTP client that only connects to public IPs on
// ports 80/443, follows at most 5 redirects (each re-validated), sends no
// cookies and times out quickly.
func NewFetcher(maxSize int64) *Fetcher {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{
		Proxy: nil, // never use environment proxies
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if port != "80" && port != "443" {
				return nil, fmt.Errorf("port %s not allowed", port)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, errors.New("no addresses")
			}
			for _, ip := range ips {
				if !IsPublicIP(ip.IP) {
					return nil, fmt.Errorf("address %s is not publicly routable", ip.IP)
				}
			}
			// Dial the validated IP directly so a second DNS lookup cannot
			// rebind to a private address (DNS rebinding).
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout:    8 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return &Fetcher{
		maxSize: maxSize,
		client: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				return validateURL(req.URL)
			},
		},
	}
}

func validateURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only http and https URLs are supported")
	}
	if u.User != nil {
		return errors.New("URLs with credentials are not allowed")
	}
	if u.Hostname() == "" {
		return errors.New("missing host")
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return errors.New("only ports 80 and 443 are allowed")
	}
	if ip := net.ParseIP(strings.Trim(u.Hostname(), "[]")); ip != nil && !IsPublicIP(ip) {
		return errors.New("address is not publicly routable")
	}
	if h := strings.ToLower(u.Hostname()); h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return errors.New("internal hostnames are not allowed")
	}
	return nil
}

// IsPublicIP reports whether ip is globally routable (not loopback,
// private, link-local, CGNAT, multicast, unspecified, or documentation).
func IsPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // TEST-NET-1
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // TEST-NET-2
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // TEST-NET-3
			return false
		case v4[0] == 169 && v4[1] == 254: // link-local incl. 169.254.169.254 metadata
			return false
		case v4[0] >= 240: // reserved + broadcast
			return false
		case v4[0] == 0:
			return false
		}
		return true
	}
	// IPv6: reject v4-mapped handled above via To4; reject ULA (fc00::/7),
	// documentation (2001:db8::/32), 6to4/teredo of private space is rare;
	// IsPrivate covers fc00::/7.
	if len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}

// Fetched is a downloaded document.
type Fetched struct {
	URL         string
	ContentType string
	Body        []byte
}

// Get downloads rawURL with all guards applied.
func (f *Fetcher) Get(ctx context.Context, rawURL string) (*Fetched, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if err := validateURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recipe-manager/1.0; +https://github.com/brett6320/recipe-manager)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,application/ld+json,application/pdf;q=0.9,*/*;q=0.5")
	req.Header.Set("Accept-Language", "en")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("remote server returned %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxSize {
		return nil, errors.New("document too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	if int64(len(body)) > f.maxSize {
		return nil, errors.New("document too large")
	}
	return &Fetched{URL: resp.Request.URL.String(), ContentType: resp.Header.Get("Content-Type"), Body: body}, nil
}
