package importer

import (
	"net"
	"net/url"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	private := []string{"127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1", "::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"}
	for _, s := range private {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be rejected", s)
		}
	}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be accepted", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	bad := []string{"ftp://x.com/a", "http://user:pw@x.com/", "http://x.com:8080/", "http://localhost/", "http://foo.local/", "http://127.0.0.1/", "http://[::1]/", "file:///etc/passwd", "http://169.254.169.254/latest/meta-data"}
	for _, s := range bad {
		u, _ := url.Parse(s)
		if err := validateURL(u); err == nil {
			t.Errorf("%s should be rejected", s)
		}
	}
	u, _ := url.Parse("https://www.example.com/recipes/1")
	if err := validateURL(u); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}
