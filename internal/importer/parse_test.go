package importer

import (
	"os"
	"strings"
	"testing"
)

const jsonld = `{"@context":"https://schema.org","@graph":[{"@type":"WebPage","name":"x"},{"@type":["Recipe","Thing"],
"name":"Best <em>Pancakes</em>","description":"Fluffy &amp; light","recipeYield":["4","4 servings"],
"prepTime":"PT10M","cookTime":"PT1H5M","image":{"@type":"ImageObject","url":"https://img.example/p.jpg"},
"keywords":"breakfast, easy","recipeCuisine":"American",
"recipeIngredient":["1 cup flour","<b>2</b> eggs"],
"recipeInstructions":[{"@type":"HowToSection","name":"Batter","itemListElement":[{"@type":"HowToStep","text":"Mix dry."},{"@type":"HowToStep","text":"Add wet."}]},{"@type":"HowToStep","text":"Fry."}]}]}`

func TestParseJSONLD(t *testing.T) {
	r, err := ParseJSON([]byte(jsonld))
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "Best Pancakes" || r.Description != "Fluffy & light" {
		t.Errorf("title/desc: %q / %q", r.Title, r.Description)
	}
	if r.Servings != "4, 4 servings" {
		t.Errorf("servings %q", r.Servings)
	}
	if r.PrepMinutes == nil || *r.PrepMinutes != 10 || r.CookMinutes == nil || *r.CookMinutes != 65 {
		t.Errorf("times %v %v", r.PrepMinutes, r.CookMinutes)
	}
	if r.ImageURL != "https://img.example/p.jpg" {
		t.Errorf("image %q", r.ImageURL)
	}
	if strings.Join(r.Ingredients, "|") != "1 cup flour|2 eggs" {
		t.Errorf("ingredients %v", r.Ingredients)
	}
	if strings.Join(r.Steps, "|") != "Batter:|Mix dry.|Add wet.|Fry." {
		t.Errorf("steps %v", r.Steps)
	}
	if strings.Join(r.Tags, ",") != "breakfast,easy,american" {
		t.Errorf("tags %v", r.Tags)
	}
}

func TestParseJSONRejects(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("expected error for non-recipe JSON")
	}
	if _, err := ParseJSON([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseHTMLWithJSONLD(t *testing.T) {
	page := `<html><head><title>Site</title><script type="application/ld+json">` + jsonld + `</script></head><body><h1>Ignored</h1><script>alert(1)</script></body></html>`
	r, err := ParseHTML([]byte(page), "https://example.com/r")
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "Best Pancakes" || r.SourceURL != "https://example.com/r" {
		t.Errorf("got %q %q", r.Title, r.SourceURL)
	}
}

func TestParseHTMLHeuristic(t *testing.T) {
	page := `<html><body><nav>Home</nav><h1>Grandma's Soup</h1><p>Serves 6. Prep time: 15 min. Cook time 1 hr 10 min</p>
	<h2>Ingredients</h2><ul><li>2 carrots</li><li>1 onion</li></ul>
	<h2>Method</h2><ol><li>Chop.</li><li>Simmer.</li></ol><h2>Nutrition</h2><p>lots</p><script>evil()</script></body></html>`
	r, err := ParseHTML([]byte(page), "https://example.com/soup")
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "Grandma's Soup" {
		t.Errorf("title %q", r.Title)
	}
	if strings.Join(r.Ingredients, "|") != "2 carrots|1 onion" {
		t.Errorf("ingredients %v", r.Ingredients)
	}
	if strings.Join(r.Steps, "|") != "Chop.|Simmer." {
		t.Errorf("steps %v", r.Steps)
	}
	if r.Servings != "6" || r.PrepMinutes == nil || *r.PrepMinutes != 15 || r.CookMinutes == nil || *r.CookMinutes != 70 {
		t.Errorf("meta %q %v %v", r.Servings, r.PrepMinutes, r.CookMinutes)
	}
	for _, s := range append(r.Ingredients, r.Steps...) {
		if strings.Contains(s, "evil") || strings.Contains(s, "lots") {
			t.Errorf("leaked %q", s)
		}
	}
}

func TestParseTextNumbered(t *testing.T) {
	r := ParseText("Toast\n\nIngredients\n- bread\n- butter\n\nDirections\n1. Toast bread. 2. Spread butter. 3. Eat.\n")
	if len(r.Steps) != 3 || r.Steps[1] != "Spread butter." {
		t.Errorf("steps %v", r.Steps)
	}
	if len(r.Ingredients) != 2 || r.Ingredients[0] != "bread" {
		t.Errorf("ingredients %v", r.Ingredients)
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]int{"PT1H30M": 90, "PT45M": 45, "P1DT2H": 1560, "1 hr 20 mins": 80, "25 minutes": 25}
	for in, want := range cases {
		got := parseDuration(in)
		if got == nil || *got != want {
			t.Errorf("%s: got %v want %d", in, got, want)
		}
	}
	if parseDuration("soon") != nil {
		t.Error("garbage should be nil")
	}
}

func TestParsePDF(t *testing.T) {
	data, err := os.ReadFile("testdata/lemonade.pdf")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "Lemonade" || len(r.Ingredients) != 2 || len(r.Steps) != 1 {
		t.Errorf("got title=%q ing=%v steps=%v", r.Title, r.Ingredients, r.Steps)
	}
	if _, err := ParsePDF([]byte("hello")); err == nil {
		t.Error("non-PDF should fail")
	}
	if _, err := ParsePDF([]byte("%PDF-1.4 garbage")); err == nil {
		t.Error("corrupt PDF should fail, not panic")
	}
}

func TestDetect(t *testing.T) {
	if detect([]byte("%PDF-1.4"), "", "") != "pdf" || detect([]byte(`{"a":1}`), "", "") != "json" ||
		detect([]byte("<!DOCTYPE html><html>"), "", "") != "html" || detect([]byte("plain"), "text/plain", "") != "text" ||
		detect([]byte("x"), "text/html; charset=utf-8", "") != "html" || detect([]byte("x"), "", "r.json") != "json" {
		t.Error("detect mismatch")
	}
}
