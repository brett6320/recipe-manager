package server

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func (e *testEnv) postMultipart(path string, fields map[string]string, filename, fileCT string, file []byte) (*http.Response, string) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if filename != "" {
		h := make(map[string][]string)
		h["Content-Disposition"] = []string{`form-data; name="file"; filename="` + filename + `"`}
		h["Content-Type"] = []string{fileCT}
		pw, _ := mw.CreatePart(h)
		_, _ = pw.Write(file)
	}
	_ = mw.Close()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", e.ts.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", e.ts.URL)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func TestImportFlows(t *testing.T) {
	e := newTestEnv(t)
	e.post("/setup", url.Values{"username": {"alice"}}, true)
	e.enrolTOTP()

	// Pasted text → prefilled editor, nothing stored yet.
	resp, body := e.postMultipart("/import", map[string]string{"text": "Toast\n\nIngredients\nbread\nbutter\n\nMethod\nToast it.\n"}, "", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `value="Toast"`) || !strings.Contains(body, "bread\nbutter") {
		t.Fatalf("text import: %d\n%s", resp.StatusCode, body[:min(len(body), 600)])
	}
	_, home := e.get("/")
	if strings.Contains(home, "Toast") {
		t.Fatal("import must not store the recipe before review")
	}

	// JSON upload with hostile content is sanitised.
	j := `{"@type":"Recipe","name":"<script>alert(1)</script>Soup","recipeIngredient":["x\u0000y"],"recipeInstructions":"Stir","image":"javascript:evil()","url":"https://ok.example/r"}`
	resp, body = e.postMultipart("/import", nil, "r.json", "application/json", []byte(j))
	if resp.StatusCode != 200 {
		t.Fatalf("json import: %d", resp.StatusCode)
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "javascript:") {
		t.Fatal("unsafe content leaked into editor")
	}
	// Markup is stripped from imported fields; control characters removed.
	if !strings.Contains(body, `value="alert(1)Soup"`) || !strings.Contains(body, ">xy<") {
		t.Fatalf("expected tag-stripped title and control-stripped ingredient:\n%s", body[:min(len(body), 1200)])
	}

	// PDF upload.
	pdf := readTestdata(t, "../importer/testdata/lemonade.pdf")
	resp, body = e.postMultipart("/import", nil, "l.pdf", "application/pdf", pdf)
	if resp.StatusCode != 200 || !strings.Contains(body, `value="Lemonade"`) {
		t.Fatalf("pdf import: %d", resp.StatusCode)
	}

	// SSRF attempts are refused before any connection.
	for _, u := range []string{"http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/", "http://localhost/", "file:///etc/passwd", "http://10.0.0.1/"} {
		resp, body = e.postMultipart("/import", map[string]string{"url": u}, "", "", nil)
		if resp.StatusCode != 400 || !strings.Contains(body, "Import failed") {
			t.Errorf("%s should be rejected, got %d", u, resp.StatusCode)
		}
	}

	// Empty submission.
	resp, _ = e.postMultipart("/import", map[string]string{}, "", "", nil)
	if resp.StatusCode != 400 {
		t.Errorf("empty import: %d", resp.StatusCode)
	}
}

func readTestdata(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
