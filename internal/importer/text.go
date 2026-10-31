package importer

import (
	"regexp"
	"strings"

	"github.com/brett6320/recipe-manager/internal/recipes"
)

var (
	ingredientsHdr = regexp.MustCompile(`(?i)^\W*(ingredients?|you will need|what you need|shopping list)\W*$`)
	stepsHdr       = regexp.MustCompile(`(?i)^\W*(instructions?|directions?|method|steps?|preparation|how to make( it)?|procedure)\W*$`)
	notesHdr       = regexp.MustCompile(`(?i)^\W*(notes?|tips?|chef'?s notes?)\W*$`)
	stopHdr        = regexp.MustCompile(`(?i)^\W*(nutrition( facts| information)?|comments?|reviews?|related recipes?|you might also like)\W*$`)
	servesRe       = regexp.MustCompile(`(?i)\b(serves|servings?|yield|makes)\b\s*:?\s*([0-9]+(?:\s*[-–to]+\s*[0-9]+)?[^.\n]{0,20})`)
	prepRe         = regexp.MustCompile(`(?i)\bprep(?:aration)?(?: time)?\s*:?\s*([0-9]+\s*(?:hours?|hrs?|h|minutes?|mins?|m)(?:\s*[0-9]+\s*(?:minutes?|mins?|m))?)`)
	cookRe         = regexp.MustCompile(`(?i)\bcook(?:ing)?(?: time)?\s*:?\s*([0-9]+\s*(?:hours?|hrs?|h|minutes?|mins?|m)(?:\s*[0-9]+\s*(?:minutes?|mins?|m))?)`)
	numberedRe     = regexp.MustCompile(`^\s*(?:step\s*)?\d+[.)\]:]\s+`)
	bulletRe       = regexp.MustCompile(`^\s*[-•*▢◻□■●○·]\s*`)
	splitNumRe     = regexp.MustCompile(`(?:^|\s)(?:\d{1,2}[.)]\s+)`)
)

// ParseText applies heuristics to free text (PDF output, pasted recipe) to
// find a title, ingredients and steps. It never fails; the result may be
// partial and is shown to the user for correction.
func ParseText(raw string) *recipes.Recipe {
	r := &recipes.Recipe{}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	section := "pre"
	var pre []string
	for _, line := range lines {
		l := recipes.Clean(line, recipes.MaxLine)
		if l == "" {
			continue
		}
		switch {
		case ingredientsHdr.MatchString(l):
			section = "ing"
			continue
		case stepsHdr.MatchString(l):
			section = "steps"
			continue
		case notesHdr.MatchString(l):
			section = "notes"
			continue
		case stopHdr.MatchString(l):
			section = "stop"
			continue
		}
		switch section {
		case "pre":
			pre = append(pre, l)
		case "ing":
			l = bulletRe.ReplaceAllString(l, "")
			if l != "" {
				r.Ingredients = append(r.Ingredients, l)
			}
		case "steps":
			l = bulletRe.ReplaceAllString(l, "")
			l = numberedRe.ReplaceAllString(l, "")
			if l != "" {
				r.Steps = append(r.Steps, l)
			}
		case "notes":
			r.Notes += l + "\n"
		}
	}
	if len(pre) > 0 {
		r.Title = pre[0]
		rest := strings.Join(pre[1:], "\n")
		if m := servesRe.FindStringSubmatch(rest); m != nil {
			r.Servings = strings.TrimSpace(m[2])
		}
		if m := prepRe.FindStringSubmatch(rest); m != nil {
			r.PrepMinutes = parseDuration(m[1])
		}
		if m := cookRe.FindStringSubmatch(rest); m != nil {
			r.CookMinutes = parseDuration(m[1])
		}
		// Keep short leading prose as description, drop metadata lines.
		var desc []string
		for _, l := range pre[1:] {
			if servesRe.MatchString(l) || prepRe.MatchString(l) || cookRe.MatchString(l) || len(l) < 3 {
				continue
			}
			desc = append(desc, l)
			if len(desc) >= 3 {
				break
			}
		}
		r.Description = strings.Join(desc, "\n")
	}
	// Single giant step → split on "1. 2. 3." markers.
	if len(r.Steps) == 1 {
		r.Steps = splitNumbered(r.Steps[0])
	}
	_ = r.Validate()
	return r
}

// splitNumbered breaks "1. Do x. 2. Do y." into separate steps when at
// least two markers are present; otherwise returns the input unchanged.
func splitNumbered(s string) []string {
	idx := splitNumRe.FindAllStringIndex(s, -1)
	if len(idx) < 2 {
		return []string{s}
	}
	var out []string
	for i, m := range idx {
		end := len(s)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		part := strings.TrimSpace(s[m[1]:end])
		if part != "" {
			out = append(out, part)
		}
	}
	if lead := strings.TrimSpace(s[:idx[0][0]]); lead != "" {
		out = append([]string{lead}, out...)
	}
	return out
}
