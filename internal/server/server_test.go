package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/brett6320/recipe-manager/internal/config"
	"github.com/brett6320/recipe-manager/internal/db"
)

type testEnv struct {
	t      *testing.T
	ts     *httptest.Server
	client *http.Client
	s      *Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(context.Background(), dir+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	u, _ := url.Parse(ts.URL)
	cfg := &config.Config{
		Listen: u.Host, DataDir: dir, PublicURL: u, RPID: "localhost", Origin: ts.URL,
		DevInsecure: true, SessionTTL: time.Hour, SessionIdle: time.Hour, ImportMaxSize: 8 << 20,
	}
	s, err := New(cfg, database, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	return &testEnv{t: t, ts: ts, client: client, s: s}
}

func (e *testEnv) get(path string) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", e.ts.URL+path, nil)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func (e *testEnv) post(path string, form url.Values, origin bool) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin {
		req.Header.Set("Origin", e.ts.URL)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func (e *testEnv) newClient() {
	jar, _ := cookiejar.New(nil)
	e.client.Jar = jar
}

var secretRe = regexp.MustCompile(`<code>([A-Z2-7]+)</code>`)

func TestAuthFlow(t *testing.T) {
	e := newTestEnv(t)

	// Fresh instance redirects to setup.
	resp, _ := e.get("/login")
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("expected redirect to /setup, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// CSRF: POST without Origin is rejected.
	resp, _ = e.post("/setup", url.Values{"username": {"alice"}}, false)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 without origin, got %d", resp.StatusCode)
	}

	// Create first admin.
	resp, _ = e.post("/setup", url.Values{"username": {"Alice"}, "display_name": {"Alice"}}, true)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/security" {
		t.Fatalf("setup: got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Setup is now closed.
	resp, _ = e.post("/setup", url.Values{"username": {"mallory"}}, true)
	if resp.StatusCode != 403 {
		t.Fatalf("second setup should be 403, got %d", resp.StatusCode)
	}

	// Not enrolled: app redirects to /security.
	resp, _ = e.get("/")
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/security" {
		t.Fatalf("unenrolled user should be sent to /security, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Begin TOTP, grab the secret from the page.
	resp, body := e.post("/security/totp/begin", nil, true)
	if resp.StatusCode != 200 {
		t.Fatalf("totp begin: %d", resp.StatusCode)
	}
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("secret not found in page")
	}
	secret := m[1]

	// Wrong code rejected.
	resp, _ = e.post("/security/totp/confirm", url.Values{"code": {"000000"}}, true)
	resp2, _ := e.get("/")
	if resp2.StatusCode != 303 {
		t.Fatal("still should not be enrolled")
	}
	_ = resp

	code, _ := totp.GenerateCode(secret, time.Now())
	resp, _ = e.post("/security/totp/confirm", url.Values{"code": {code}}, true)
	if resp.StatusCode != 303 {
		t.Fatalf("confirm: %d", resp.StatusCode)
	}

	// Enrolled: home page works.
	resp, body = e.get("/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Sign out") {
		t.Fatalf("home after enrol: %d", resp.StatusCode)
	}

	// Logout.
	resp, _ = e.post("/logout", nil, true)
	if resp.StatusCode != 303 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp, _ = e.get("/")
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/login" {
		t.Fatalf("after logout expected /login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Replay: the confirmation code must not log in again.
	resp, _ = e.post("/login/totp", url.Values{"username": {"alice"}, "code": {code}}, true)
	if resp.StatusCode != 401 {
		t.Fatalf("replayed code should fail, got %d", resp.StatusCode)
	}

	// Next time step logs in.
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	resp, _ = e.post("/login/totp", url.Values{"username": {"alice"}, "code": {next}}, true)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("login with next code: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = e.get("/admin")
	if resp.StatusCode != 200 {
		t.Fatalf("admin page for admin: %d", resp.StatusCode)
	}

	// Cannot remove the only method.
	e.post("/security/totp/remove", nil, true)
	if !strings.Contains(mustBody(e, "/security"), "enabled") {
		t.Fatal("TOTP should still be enabled")
	}

	// Invite flow.
	resp, _ = e.post("/admin/invites", nil, true)
	if resp.StatusCode != 303 {
		t.Fatalf("invite: %d", resp.StatusCode)
	}
	_, body = e.get("/admin")
	im := regexp.MustCompile(`/register\?code=([A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if im == nil {
		t.Fatal("invite link not shown")
	}
	inviteCode := im[1]

	e.newClient()
	resp, _ = e.get("/register?code=bogus")
	if resp.StatusCode != 403 {
		t.Fatalf("bogus invite: %d", resp.StatusCode)
	}
	resp, _ = e.post("/register", url.Values{"code": {inviteCode}, "username": {"bob"}}, true)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/security" {
		t.Fatalf("register: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = e.get("/admin")
	if resp.StatusCode != 303 {
		t.Fatalf("bob (unenrolled, non-admin) should be redirected, got %d", resp.StatusCode)
	}
	// Invite is single use.
	e.newClient()
	resp, _ = e.post("/register", url.Values{"code": {inviteCode}, "username": {"carol"}}, true)
	if resp.StatusCode != 403 {
		t.Fatalf("reused invite should be 403, got %d", resp.StatusCode)
	}
}

func mustBody(e *testEnv, path string) string {
	_, b := e.get(path)
	return b
}

func TestTOTPLockout(t *testing.T) {
	e := newTestEnv(t)
	e.post("/setup", url.Values{"username": {"alice"}}, true)
	_, body := e.post("/security/totp/begin", nil, true)
	secret := secretRe.FindStringSubmatch(body)[1]
	code, _ := totp.GenerateCode(secret, time.Now())
	e.post("/security/totp/confirm", url.Values{"code": {code}}, true)
	e.post("/logout", nil, true)

	for i := 0; i < 5; i++ {
		resp, _ := e.post("/login/totp", url.Values{"username": {"alice"}, "code": {"111111"}}, true)
		if resp.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	good, _ := totp.GenerateCode(secret, time.Now().Add(60*time.Second))
	resp, body := e.post("/login/totp", url.Values{"username": {"alice"}, "code": {good}}, true)
	if resp.StatusCode != 401 || !strings.Contains(body, "Too many attempts") {
		t.Fatalf("expected lockout, got %d", resp.StatusCode)
	}
}

func TestWebAuthnBeginEndpoints(t *testing.T) {
	e := newTestEnv(t)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", e.ts.URL+"/api/webauthn/login/begin", strings.NewReader("{}"))
	req.Header.Set("Origin", e.ts.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"challenge"`) || !strings.Contains(string(b), `"rpId"`) {
		t.Fatalf("login begin: %d %s", resp.StatusCode, b)
	}
	// Registration begin requires a session.
	req, _ = http.NewRequestWithContext(context.Background(), "POST", e.ts.URL+"/api/webauthn/register/begin", strings.NewReader("{}"))
	req.Header.Set("Origin", e.ts.URL)
	resp2, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Fatalf("register begin without session: %d", resp2.StatusCode)
	}
}
