package importer

import (
	"bytes"
	"context"
	"errors"
	"mime"
	"strings"

	"github.com/brett6320/recipe-manager/internal/recipes"
)

// Result is a parsed recipe plus a non-fatal warning for the user.
type Result struct {
	Recipe  *recipes.Recipe
	Warning string
}

// FromURL downloads and parses a remote page.
func (f *Fetcher) FromURL(ctx context.Context, rawURL string) (*Result, error) {
	doc, err := f.Get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	res, err := FromBytes(doc.Body, doc.ContentType, "", doc.URL)
	if err != nil {
		return nil, err
	}
	if res.Recipe.SourceURL == "" {
		res.Recipe.SourceURL = doc.URL
	}
	return res, nil
}

// FromBytes dispatches on content type / filename / sniffing.
func FromBytes(data []byte, contentType, filename, sourceURL string) (*Result, error) {
	if len(data) == 0 {
		return nil, errors.New("empty document")
	}
	kind := detect(data, contentType, filename)
	var r *recipes.Recipe
	var err error
	switch kind {
	case "pdf":
		r, err = ParsePDF(data)
	case "json":
		r, err = ParseJSON(data)
	case "html":
		r, err = ParseHTML(data, sourceURL)
		if err != nil && r != nil {
			return &Result{Recipe: r, Warning: err.Error()}, nil
		}
	default:
		r = ParseText(string(data))
		if r.Title == "" {
			return nil, errors.New("could not find any recipe text")
		}
	}
	if err != nil {
		return nil, err
	}
	if r.Title == "" {
		r.Title = "Imported recipe"
	}
	var warn string
	if len(r.Ingredients) == 0 || len(r.Steps) == 0 {
		warn = "Some sections could not be detected; please check ingredients and method."
	}
	return &Result{Recipe: r, Warning: warn}, nil
}

func detect(data []byte, contentType, filename string) string {
	ct := strings.ToLower(contentType)
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		ct = mt
	}
	ext := strings.ToLower(filename)
	switch {
	case bytes.HasPrefix(data, []byte("%PDF-")), ct == "application/pdf", strings.HasSuffix(ext, ".pdf"):
		return "pdf"
	case ct == "application/json", ct == "application/ld+json", strings.HasSuffix(ext, ".json"):
		return "json"
	case strings.Contains(ct, "html"), strings.HasSuffix(ext, ".html"), strings.HasSuffix(ext, ".htm"):
		return "html"
	}
	trim := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	switch {
	case len(trim) > 0 && (trim[0] == '{' || trim[0] == '['):
		return "json"
	case bytes.HasPrefix(bytes.ToLower(trim[:min(len(trim), 64)]), []byte("<!doctype")), bytes.HasPrefix(bytes.ToLower(trim[:min(len(trim), 8)]), []byte("<html")), bytes.Contains(trim[:min(len(trim), 4096)], []byte("<body")):
		return "html"
	}
	return "text"
}
