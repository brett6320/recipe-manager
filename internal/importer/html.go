package importer

import (
	"bytes"
	"errors"
	"strings"

	"golang.org/x/net/html"

	"github.com/brett6320/recipe-manager/internal/recipes"
)

// ParseHTML extracts a recipe from an HTML document: JSON-LD first, then a
// heuristic pass over the visible text.
func ParseHTML(data []byte, sourceURL string) (*recipes.Recipe, error) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("could not parse HTML")
	}
	var title string
	var jsonBlocks [][]byte
	var text strings.Builder
	var walk func(*html.Node, bool)
	walk = func(n *html.Node, skip bool) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script":
				if attr(n, "type") == "application/ld+json" && n.FirstChild != nil {
					jsonBlocks = append(jsonBlocks, []byte(n.FirstChild.Data))
				}
				return
			case "style", "noscript", "template", "svg", "iframe", "nav", "footer", "header":
				return
			case "title":
				if n.FirstChild != nil && title == "" {
					title = n.FirstChild.Data
				}
			case "br", "p", "div", "li", "h1", "h2", "h3", "h4", "tr", "section", "article":
				text.WriteString("\n")
			}
		}
		if n.Type == html.TextNode && !skip {
			text.WriteString(n.Data)
			text.WriteString(" ")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, skip)
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "p", "div", "li", "h1", "h2", "h3", "h4", "tr", "section", "article":
				text.WriteString("\n")
			}
		}
	}
	walk(doc, false)

	for _, b := range jsonBlocks {
		if r, err := ParseJSON(b); err == nil && r.Title != "" && (len(r.Ingredients) > 0 || len(r.Steps) > 0) {
			if r.SourceURL == "" {
				r.SourceURL = sourceURL
			}
			return r, nil
		}
	}
	r := ParseText(text.String())
	if r.Title == "" {
		r.Title = recipes.Clean(title, recipes.MaxTitle)
	}
	r.SourceURL = sourceURL
	if len(r.Ingredients) == 0 && len(r.Steps) == 0 {
		return r, errors.New("no structured recipe data found; the fields below are a best guess")
	}
	_ = r.Validate()
	return r, nil
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// htmlToText strips any markup from a string (some sites embed HTML in
// JSON-LD fields) and decodes entities.
func htmlToText(s string) string {
	if !strings.ContainsAny(s, "<&") {
		return s
	}
	var out strings.Builder
	z := html.NewTokenizer(strings.NewReader(s))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out.String()
		case html.TextToken:
			out.Write(z.Text())
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "br", "p", "li", "div":
				out.WriteString(" ")
			}
		}
	}
}
