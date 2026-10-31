package recipes

import "testing"

func TestClean(t *testing.T) {
	cases := map[string]string{
		"  hello \n world  ":            "hello world",
		"a\x00b\x1fc":                   "abc",
		"<b>bold</b>":                   "<b>bold</b>", // markup is escaped at render time by html/template
		"tab\tsep":                      "tab sep",
		"zero\u200bwidth\u202eoverride": "zerowidthoverride",
	}
	for in, want := range cases {
		if got := Clean(in, 100); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean("ééééé", 3); got != "é" {
		t.Errorf("truncate should not split runes, got %q", got)
	}
}

func TestCleanURL(t *testing.T) {
	ok := []string{"https://example.com/x?y=1", "http://a.b/c"}
	bad := []string{"javascript:alert(1)", "data:text/html,x", "ftp://x", "https://user:pw@host/", "https://x/<script>", "//example.com", " "}
	for _, u := range ok {
		if CleanURL(u) != u {
			t.Errorf("expected %q accepted", u)
		}
	}
	for _, u := range bad {
		if CleanURL(u) != "" {
			t.Errorf("expected %q rejected", u)
		}
	}
}

func TestCleanTags(t *testing.T) {
	got := CleanTags([]string{" Dinner", "#dinner", "QUICK", "", "quick"})
	if len(got) != 2 || got[0] != "dinner" || got[1] != "quick" {
		t.Errorf("got %v", got)
	}
}
