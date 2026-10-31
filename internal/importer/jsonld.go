package importer

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/brett6320/recipe-manager/internal/recipes"
)

// ParseJSON accepts schema.org/Recipe JSON (a single object, an array, a
// @graph wrapper, or our own export format which is the same schema) and
// returns the first recipe found.
func ParseJSON(data []byte) (*recipes.Recipe, error) {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("invalid JSON")
	}
	node := findRecipe(v, 0)
	if node == nil {
		return nil, errors.New("no schema.org Recipe object found")
	}
	return recipeFromNode(node), nil
}

// findRecipe walks arbitrary JSON looking for an object whose @type is (or
// includes) "Recipe".
func findRecipe(v any, depth int) map[string]any {
	if depth > 12 {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		if hasType(t, "Recipe") {
			return t
		}
		for _, key := range []string{"@graph", "mainEntity", "mainEntityOfPage", "itemListElement", "hasPart"} {
			if sub, ok := t[key]; ok {
				if r := findRecipe(sub, depth+1); r != nil {
					return r
				}
			}
		}
		// Our own export: plain object with recipeIngredient but no @type.
		if _, ok := t["recipeIngredient"]; ok {
			return t
		}
		for _, sub := range t {
			if r := findRecipe(sub, depth+1); r != nil {
				return r
			}
		}
	case []any:
		for _, item := range t {
			if r := findRecipe(item, depth+1); r != nil {
				return r
			}
		}
	}
	return nil
}

func hasType(m map[string]any, want string) bool {
	switch t := m["@type"].(type) {
	case string:
		return strings.EqualFold(t, want) || strings.HasSuffix(strings.ToLower(t), "/"+strings.ToLower(want))
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		var parts []string
		for _, x := range t {
			if s := str(x); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		for _, k := range []string{"text", "name", "url", "@id", "contentUrl"} {
			if s, ok := t[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func strList(v any) []string {
	switch t := v.(type) {
	case string:
		// Some sites ship one big string; split on newlines.
		return strings.Split(t, "\n")
	case []any:
		var out []string
		for _, x := range t {
			switch e := x.(type) {
			case string:
				out = append(out, e)
			case map[string]any:
				if hasType(e, "HowToSection") {
					if name := str(e["name"]); name != "" {
						out = append(out, name+":")
					}
					out = append(out, strList(e["itemListElement"])...)
					continue
				}
				if s := str(e); s != "" {
					out = append(out, s)
				}
			case []any:
				out = append(out, strList(e)...)
			}
		}
		return out
	case map[string]any:
		if hasType(t, "ItemList") {
			return strList(t["itemListElement"])
		}
		if s := str(t); s != "" {
			return []string{s}
		}
	}
	return nil
}

var isoDur = regexp.MustCompile(`(?i)^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// parseDuration converts an ISO-8601 duration (PT1H30M) or a loose
// "1 hr 30 min" string into minutes.
func parseDuration(s string) *int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if m := isoDur.FindStringSubmatch(s); m != nil {
		d, _ := strconv.Atoi(m[1])
		h, _ := strconv.Atoi(m[2])
		mi, _ := strconv.Atoi(m[3])
		total := d*24*60 + h*60 + mi
		if total == 0 && m[4] != "" {
			return nil
		}
		return &total
	}
	total := 0
	found := false
	for _, m := range regexp.MustCompile(`(?i)(\d+)\s*(hours?|hrs?|h|minutes?|mins?|m)\b`).FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		if strings.HasPrefix(strings.ToLower(m[2]), "h") {
			n *= 60
		}
		total += n
		found = true
	}
	if !found {
		return nil
	}
	return &total
}

func firstImage(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			return firstImage(t[0])
		}
	case map[string]any:
		return str(t)
	}
	return ""
}

func recipeFromNode(n map[string]any) *recipes.Recipe {
	r := &recipes.Recipe{
		Title:       htmlToText(str(n["name"])),
		Description: htmlToText(str(n["description"])),
		Servings:    str(n["recipeYield"]),
		SourceURL:   str(n["url"]),
		ImageURL:    firstImage(n["image"]),
		Notes:       htmlToText(str(n["comment"])),
		PrepMinutes: parseDuration(str(n["prepTime"])),
		CookMinutes: parseDuration(str(n["cookTime"])),
	}
	if r.PrepMinutes == nil && r.CookMinutes == nil {
		r.CookMinutes = parseDuration(str(n["totalTime"]))
	}
	for _, s := range strList(n["recipeIngredient"]) {
		r.Ingredients = append(r.Ingredients, htmlToText(s))
	}
	if len(r.Ingredients) == 0 {
		for _, s := range strList(n["ingredients"]) {
			r.Ingredients = append(r.Ingredients, htmlToText(s))
		}
	}
	for _, s := range strList(n["recipeInstructions"]) {
		r.Steps = append(r.Steps, splitNumbered(htmlToText(s))...)
	}
	var tags []string
	for _, k := range []string{"keywords", "recipeCategory", "recipeCuisine"} {
		tags = append(tags, strings.Split(str(n[k]), ",")...)
	}
	r.Tags = tags
	_ = r.Validate()
	return r
}
