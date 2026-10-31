package server

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// enrol creates a user via setup (first) or invite, confirms TOTP and
// returns the secret so the test can log in again later.
func (e *testEnv) enrolTOTP() string {
	e.t.Helper()
	_, body := e.post("/security/totp/begin", nil, true)
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatal("no secret")
	}
	code, _ := totp.GenerateCode(m[1], time.Now())
	e.post("/security/totp/confirm", url.Values{"code": {code}}, true)
	return m[1]
}

func (e *testEnv) loginTOTP(user, secret string, step int) {
	e.t.Helper()
	code, _ := totp.GenerateCode(secret, time.Now().Add(time.Duration(step)*30*time.Second))
	resp, _ := e.post("/login/totp", url.Values{"username": {user}, "code": {code}}, true)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		e.t.Fatalf("login %s: %d %s", user, resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRecipesAndSharing(t *testing.T) {
	e := newTestEnv(t)
	e.post("/setup", url.Values{"username": {"alice"}}, true)
	aliceSecret := e.enrolTOTP()

	// Alice: folder "Dinners", recipe inside.
	resp, _ := e.post("/folders", url.Values{"name": {"Dinners"}}, true)
	if resp.StatusCode != 303 {
		t.Fatalf("folder: %d", resp.StatusCode)
	}
	_, body := e.get("/")
	fm := regexp.MustCompile(`/folders/(\d+)`).FindStringSubmatch(body)
	if fm == nil {
		t.Fatal("folder link missing")
	}
	folderID := fm[1]
	resp, _ = e.post("/recipes", url.Values{
		"title": {"<b>Pasta</b> ​ night"}, "folder": {folderID},
		"ingredients": {"200g pasta\n\n1 tbsp salt"}, "steps": {"Boil\nDrain"}, "tags": {"Dinner, quick"},
		"source_url": {"javascript:alert(1)"}, "image_url": {"https://img.example/p.jpg"},
	}, true)
	if resp.StatusCode != 303 {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	recipePath := resp.Header.Get("Location")
	_, body = e.get(recipePath)
	if !strings.Contains(body, "&lt;b&gt;Pasta&lt;/b&gt; night") {
		t.Error("title should be HTML-escaped and zero-width chars stripped")
	}
	if strings.Contains(body, "javascript:") {
		t.Error("javascript: URL must be dropped")
	}
	if !strings.Contains(body, `href="/search?tag=dinner"`) || !strings.Contains(body, "200g pasta") {
		t.Error("tags/ingredients missing")
	}

	// Invite bob.
	e.post("/admin/invites", nil, true)
	_, body = e.get("/admin")
	inv := regexp.MustCompile(`/register\?code=([A-Za-z0-9_-]+)`).FindStringSubmatch(body)[1]

	e.newClient()
	e.post("/register", url.Values{"code": {inv}, "username": {"bob"}}, true)
	bobSecret := e.enrolTOTP()
	// Bob sees nothing of alice's.
	resp, _ = e.get(recipePath)
	if resp.StatusCode != 404 {
		t.Fatalf("bob should get 404, got %d", resp.StatusCode)
	}
	resp, _ = e.get("/folders/" + folderID)
	if resp.StatusCode != 404 {
		t.Fatalf("bob folder should be 404, got %d", resp.StatusCode)
	}
	// Bob cannot share alice's things either.
	resp, _ = e.post("/shares", url.Values{"subject_type": {"folder"}, "subject_id": {folderID}, "grantee_type": {"user"}, "user": {"bob"}, "perm": {"edit"}}, true)
	if resp.StatusCode != 404 {
		t.Fatalf("bob share attempt: %d", resp.StatusCode)
	}

	// Alice shares the folder (view) with bob.
	e.newClient()
	e.loginTOTP("alice", aliceSecret, 1)
	resp, _ = e.post("/shares", url.Values{"subject_type": {"folder"}, "subject_id": {folderID}, "grantee_type": {"user"}, "user": {"bob"}, "perm": {"view"}}, true)
	if resp.StatusCode != 303 {
		t.Fatalf("share: %d", resp.StatusCode)
	}

	e.newClient()
	e.loginTOTP("bob", bobSecret, 1)
	resp, body = e.get(recipePath)
	if resp.StatusCode != 200 || !strings.Contains(body, "you can view") {
		t.Fatalf("bob view after share: %d", resp.StatusCode)
	}
	resp, _ = e.get(recipePath + "/edit")
	if resp.StatusCode != 403 {
		t.Fatalf("bob edit with view perm: %d", resp.StatusCode)
	}
	resp, _ = e.post(recipePath+"/delete", nil, true)
	if resp.StatusCode != 404 {
		t.Fatalf("bob delete: %d", resp.StatusCode)
	}
	_, body = e.get("/")
	if !strings.Contains(body, "Shared with me") {
		t.Error("home should list shared folder")
	}
	resp, body = e.get(recipePath + "/export.json")
	if resp.StatusCode != 200 || !strings.Contains(body, `"@type":"Recipe"`) {
		t.Fatalf("export: %d %s", resp.StatusCode, body)
	}
	// Open-redirect guard on share removal.
	resp, _ = e.post("/shares/1/delete", url.Values{"back": {"https://evil.example/"}}, true)
	if resp.Header.Get("Location") != "/" {
		t.Errorf("redirect should be /, got %q", resp.Header.Get("Location"))
	}
}
