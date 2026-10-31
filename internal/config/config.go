// Package config loads runtime configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	Listen        string
	DataDir       string
	PublicURL     *url.URL
	RPID          string
	Origin        string
	TrustedProxy  []*net.IPNet
	RequireProxy  bool
	TLSCert       string
	TLSKey        string
	TLSClientCA   string
	DevInsecure   bool
	LogJSON       bool
	SessionTTL    time.Duration
	SessionIdle   time.Duration
	ImportMaxSize int64
}

// cloudflareRanges are Cloudflare's published egress ranges
// (https://www.cloudflare.com/ips/). Refresh when Cloudflare updates them.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		Listen:        env("RM_LISTEN", "127.0.0.1:8080"),
		DataDir:       env("RM_DATA_DIR", "./data"),
		TLSCert:       env("RM_TLS_CERT", ""),
		TLSKey:        env("RM_TLS_KEY", ""),
		TLSClientCA:   env("RM_TLS_CLIENT_CA", ""),
		ImportMaxSize: 8 << 20,
	}
	var err error
	if c.DevInsecure, err = envBool("RM_DEV_INSECURE", false); err != nil {
		return nil, err
	}
	if c.RequireProxy, err = envBool("RM_REQUIRE_PROXY", false); err != nil {
		return nil, err
	}
	if c.LogJSON, err = envBool("RM_LOG_JSON", true); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = envDuration("RM_SESSION_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if c.SessionIdle, err = envDuration("RM_SESSION_IDLE", 7*24*time.Hour); err != nil {
		return nil, err
	}

	raw := env("RM_PUBLIC_URL", "")
	if raw == "" {
		return nil, errors.New("RM_PUBLIC_URL is required (e.g. https://recipes.example.com)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("RM_PUBLIC_URL must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !c.DevInsecure {
		return nil, errors.New("RM_PUBLIC_URL uses http; set RM_DEV_INSECURE=true for local development only")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("RM_PUBLIC_URL must not include a path")
	}
	u.Path = ""
	c.PublicURL = u
	c.RPID = u.Hostname()
	c.Origin = u.Scheme + "://" + u.Host

	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("RM_TLS_CERT and RM_TLS_KEY must be set together")
	}
	if c.TLSClientCA != "" && c.TLSCert == "" {
		return nil, errors.New("RM_TLS_CLIENT_CA requires RM_TLS_CERT/RM_TLS_KEY")
	}

	for _, part := range strings.Split(env("RM_TRUSTED_PROXIES", "cloudflare"), ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
			continue
		case strings.EqualFold(part, "cloudflare"):
			for _, cidr := range cloudflareRanges {
				_, n, _ := net.ParseCIDR(cidr)
				c.TrustedProxy = append(c.TrustedProxy, n)
			}
		case strings.EqualFold(part, "none"):
			c.TrustedProxy = nil
		default:
			if !strings.Contains(part, "/") {
				if ip := net.ParseIP(part); ip != nil {
					if ip.To4() != nil {
						part += "/32"
					} else {
						part += "/128"
					}
				}
			}
			_, n, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("RM_TRUSTED_PROXIES: invalid entry %q", part)
			}
			c.TrustedProxy = append(c.TrustedProxy, n)
		}
	}
	return c, nil
}
