// Package recipes stores recipes, folders, groups and shares.
package recipes

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits applied to every stored field, whether typed or imported.
const (
	MaxTitle       = 200
	MaxDescription = 2000
	MaxLine        = 1000
	MaxNotes       = 5000
	MaxItems       = 200
	MaxTags        = 30
	MaxTag         = 40
	MaxURL         = 2048
	MaxFolderName  = 80
)

// Recipe is a stored recipe.
type Recipe struct {
	ID          int64
	OwnerID     int64
	OwnerName   string
	FolderID    *int64
	Title       string
	Description string
	Servings    string
	PrepMinutes *int
	CookMinutes *int
	SourceURL   string
	ImageURL    string
	Notes       string
	Ingredients []string
	Steps       []string
	Tags        []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Perm is an access level.
type Perm string

const (
	PermNone  Perm = ""
	PermView  Perm = "view"
	PermEdit  Perm = "edit"
	PermOwner Perm = "owner"
)

// CanView reports whether p allows reading.
func (p Perm) CanView() bool { return p != PermNone }

// CanEdit reports whether p allows writing.
func (p Perm) CanEdit() bool { return p == PermEdit || p == PermOwner }

// Folder is a node in a user's virtual folder tree.
type Folder struct {
	ID       int64
	OwnerID  int64
	ParentID *int64
	Name     string
	Path     string // "/" separated display path
}

// Group is a named set of users.
type Group struct {
	ID        int64
	Name      string
	OwnerID   int64
	OwnerName string
	Members   int
}

// Share is one grant.
type Share struct {
	ID          int64
	SubjectType string
	SubjectID   int64
	GranteeType string
	GranteeID   int64
	GranteeName string
	Perm        Perm
}

// Clean normalises free text: strips control and non-printable characters
// (including zero-width and bidi overrides), collapses whitespace and
// enforces a maximum length. Every imported or user supplied string passes
// through here (or CleanMultiline) before storage.
func Clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	return truncate(s, max)
}

// CleanMultiline keeps paragraph breaks but otherwise behaves like Clean.
func CleanMultiline(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}
	s = strings.TrimSpace(strings.Join(lines, "\n"))
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return truncate(s, max)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// CleanLines cleans each line and drops empties.
func CleanLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = Clean(l, MaxLine)
		if l == "" {
			continue
		}
		out = append(out, l)
		if len(out) >= MaxItems {
			break
		}
	}
	return out
}

// CleanTags lower-cases, dedupes and limits tags.
func CleanTags(tags []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(Clean(t, MaxTag))
		t = strings.Trim(t, "#,; ")
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= MaxTags {
			break
		}
	}
	return out
}

// CleanURL accepts only absolute http(s) URLs without credentials or
// suspicious characters and returns "" for anything else.
func CleanURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxURL {
		return ""
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}
	if strings.ContainsAny(raw, " \t\n\r\"'<>\\`{}|^") || strings.Contains(raw, "@") {
		return ""
	}
	return raw
}

// Validate applies all cleaning rules and checks required fields.
func (r *Recipe) Validate() error {
	r.Title = Clean(r.Title, MaxTitle)
	if r.Title == "" {
		return errors.New("title is required")
	}
	r.Description = CleanMultiline(r.Description, MaxDescription)
	r.Servings = Clean(r.Servings, 60)
	r.SourceURL = CleanURL(r.SourceURL)
	r.ImageURL = CleanURL(r.ImageURL)
	r.Notes = CleanMultiline(r.Notes, MaxNotes)
	r.Ingredients = CleanLines(r.Ingredients)
	r.Steps = CleanLines(r.Steps)
	r.Tags = CleanTags(r.Tags)
	if r.PrepMinutes != nil && (*r.PrepMinutes < 0 || *r.PrepMinutes > 100000) {
		r.PrepMinutes = nil
	}
	if r.CookMinutes != nil && (*r.CookMinutes < 0 || *r.CookMinutes > 100000) {
		r.CookMinutes = nil
	}
	return nil
}

// TotalMinutes sums prep and cook time.
func (r *Recipe) TotalMinutes() int {
	n := 0
	if r.PrepMinutes != nil {
		n += *r.PrepMinutes
	}
	if r.CookMinutes != nil {
		n += *r.CookMinutes
	}
	return n
}
