//go:build ignore

// Command screenshots drives a headless Chrome against a local dev instance
// to seed demo data and capture the images used in docs/. Usage:
//
//	go run tools/screenshots/main.go -base http://localhost:8765 -out docs/screenshots
//
// It expects a fresh, empty instance started with RM_DEV_INSECURE=true.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/net/websocket"
)

var (
	base = flag.String("base", "http://localhost:8765", "app base URL")
	out  = flag.String("out", "docs/screenshots", "output directory")
	chr  = flag.String("chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "chrome binary")
	port = flag.Int("port", 9333, "devtools port")
)

type cdp struct {
	ws  *websocket.Conn
	seq atomic.Int64
}

func (c *cdp) call(method string, params any) (json.RawMessage, error) {
	id := c.seq.Add(1)
	req := map[string]any{"id": id, "method": method, "params": params}
	if err := websocket.JSON.Send(c.ws, req); err != nil {
		return nil, err
	}
	for {
		var msg struct {
			ID     int64                     `json:"id"`
			Result json.RawMessage           `json:"result"`
			Error  *struct{ Message string } `json:"error"`
		}
		var raw string
		if err := websocket.Message.Receive(c.ws, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			continue
		}
		if msg.ID != id {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("%s: %s", method, msg.Error.Message)
		}
		return msg.Result, nil
	}
}

func (c *cdp) eval(js string) (string, error) {
	res, err := c.call("Runtime.evaluate", map[string]any{"expression": js, "awaitPromise": true, "returnByValue": true})
	if err != nil {
		return "", err
	}
	var r struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string                       `json:"text"`
			Exception struct{ Description string } `json:"exception"`
		} `json:"exceptionDetails"`
	}
	_ = json.Unmarshal(res, &r)
	if r.ExceptionDetails != nil {
		return "", fmt.Errorf("js: %s %s", r.ExceptionDetails.Text, r.ExceptionDetails.Exception.Description)
	}
	if s, ok := r.Result.Value.(string); ok {
		return s, nil
	}
	b, _ := json.Marshal(r.Result.Value)
	return string(b), nil
}

func (c *cdp) nav(path string) {
	must(c.call("Page.navigate", map[string]any{"url": *base + path}))
	c.waitLoad()
}

func (c *cdp) waitLoad() {
	for i := 0; i < 100; i++ {
		time.Sleep(50 * time.Millisecond)
		s, err := c.eval(`document.readyState`)
		if err == nil && s == "complete" {
			time.Sleep(150 * time.Millisecond)
			return
		}
	}
}

// post submits a form from inside the page so Origin/cookies behave exactly
// like a real browser submission, then waits for the resulting navigation.
func (c *cdp) post(action string, fields map[string]string) {
	b, _ := json.Marshal(fields)
	js := fmt.Sprintf(`(() => { const f = document.createElement('form'); f.method='post'; f.action=%q;
		for (const [k,v] of Object.entries(%s || {})) { const i=document.createElement('textarea'); i.name=k; i.value=v; f.appendChild(i); }
		document.body.appendChild(f); f.submit(); return 'ok'; })()`, action, b)
	must(c.eval(js))
	time.Sleep(300 * time.Millisecond)
	c.waitLoad()
}

func (c *cdp) shot(name string) {
	res := must(c.call("Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}))
	var r struct{ Data string }
	_ = json.Unmarshal(res, &r)
	data, _ := base64.StdEncoding.DecodeString(r.Data)
	p := filepath.Join(*out, name+".png")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s (%d bytes)", p, len(data))
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func main() {
	flag.Parse()
	_ = os.MkdirAll(*out, 0o755)
	profile, _ := os.MkdirTemp("", "rm-shots-")
	defer os.RemoveAll(profile)
	cmd := exec.Command(*chr, "--headless=new", fmt.Sprintf("--remote-debugging-port=%d", *port), "--user-data-dir="+profile,
		"--window-size=1280,860", "--hide-scrollbars", "--remote-allow-origins=*", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var wsURL string
	for i := 0; i < 50 && wsURL == ""; i++ {
		time.Sleep(200 * time.Millisecond)
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json", *port))
		if err != nil {
			continue
		}
		var targets []struct {
			Type string `json:"type"`
			WS   string `json:"webSocketDebuggerUrl"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&targets)
		resp.Body.Close()
		for _, t := range targets {
			if t.Type == "page" {
				wsURL = t.WS
			}
		}
	}
	if wsURL == "" {
		log.Fatal("chrome did not expose a page target")
	}
	ws := must(websocket.Dial(wsURL, "", "http://127.0.0.1"))
	c := &cdp{ws: ws}
	must(c.call("Page.enable", map[string]any{}))
	must(c.call("Emulation.setDeviceMetricsOverride", map[string]any{"width": 1280, "height": 860, "deviceScaleFactor": 1, "mobile": false}))

	// 1. First-run setup.
	c.nav("/setup")
	c.shot("01-setup")
	c.post("/setup", map[string]string{"username": "brett", "display_name": "Brett"})

	// 2. Enrol TOTP.
	c.post("/security/totp/begin", nil)
	html := must(c.eval(`document.documentElement.outerHTML`))
	secret := regexp.MustCompile(`<code>([A-Z2-7]+)</code>`).FindStringSubmatch(html)
	if secret == nil {
		log.Fatal("no TOTP secret on page")
	}
	c.shot("02-totp-enrol")
	code := must(totp.GenerateCode(secret[1], time.Now()))
	c.post("/security/totp/confirm", map[string]string{"code": code})
	c.shot("03-security")

	// 3. Seed folders, groups and recipes.
	c.post("/folders", map[string]string{"name": "Dinners"})
	c.post("/folders", map[string]string{"name": "Baking"})
	c.post("/folders", map[string]string{"name": "Weeknight"})
	c.nav("/")
	html = must(c.eval(`document.documentElement.outerHTML`))
	folderIDs := map[string]string{}
	for _, m := range regexp.MustCompile(`href="/folders/(\d+)">📁 ([^<]+)<`).FindAllStringSubmatch(html, -1) {
		folderIDs[m[2]] = m[1]
	}
	c.post("/folders", map[string]string{"name": "Italian", "parent": folderIDs["Dinners"]})
	c.post("/folders", map[string]string{"name": "Mexican", "parent": folderIDs["Dinners"]})
	c.post("/groups", map[string]string{"name": "Family"})
	c.post("/groups", map[string]string{"name": "Supper Club"})

	c.nav("/folders/" + folderIDs["Dinners"])
	html = must(c.eval(`document.documentElement.outerHTML`))
	for _, m := range regexp.MustCompile(`href="/folders/(\d+)">📁 ([^<]+)<`).FindAllStringSubmatch(html, -1) {
		folderIDs[m[2]] = m[1]
	}

	recipes := []map[string]string{
		{"title": "Weeknight Bolognese", "folder": folderIDs["Italian"], "servings": "4", "prep_minutes": "15", "cook_minutes": "45", "tags": "dinner, italian, pasta",
			"description": "A quick ragù that still tastes like it simmered all afternoon.",
			"ingredients": "1 tbsp olive oil\n1 onion, finely diced\n2 cloves garlic\n500 g beef mince\n2 tbsp tomato paste\n400 g tin chopped tomatoes\n150 ml red wine\nSalt and pepper\n400 g spaghetti\nParmesan, to serve",
			"steps":       "Sweat the onion in oil until soft, then add garlic for a minute.\nBrown the mince in batches, breaking it up.\nStir in tomato paste and cook for two minutes.\nAdd wine, tomatoes and a splash of water; simmer 35 minutes.\nCook spaghetti, toss with sauce, finish with parmesan.",
			"image_url":   "https://images.unsplash.com/photo-1621996346565-e3dbc646d9a9?w=1200"},
		{"title": "Chicken Tinga Tacos", "folder": folderIDs["Mexican"], "servings": "4", "prep_minutes": "10", "cook_minutes": "30", "tags": "dinner, mexican, chicken",
			"ingredients": "600 g chicken thighs\n1 onion\n2 chipotles in adobo\n400 g tin tomatoes\n1 tsp oregano\n12 corn tortillas\nLime, coriander, crema",
			"steps":       "Poach the chicken until cooked; shred.\nBlend onion, chipotles, tomatoes and oregano; fry the sauce 10 minutes.\nFold in chicken and simmer.\nWarm tortillas and serve with lime, coriander and crema."},
		{"title": "Overnight Sourdough", "folder": folderIDs["Baking"], "servings": "1 loaf", "prep_minutes": "30", "cook_minutes": "45", "tags": "baking, bread",
			"ingredients": "500 g bread flour\n350 g water\n100 g active starter\n10 g salt",
			"steps":       "Mix flour and water; rest 1 hour.\nAdd starter and salt; four sets of stretch-and-folds over 2 hours.\nShape, then proof in the fridge overnight.\nBake in a preheated Dutch oven: 20 min lid on, 25 min lid off."},
		{"title": "Sheet-Pan Lemon Chicken", "folder": folderIDs["Weeknight"], "servings": "4", "prep_minutes": "10", "cook_minutes": "35", "tags": "dinner, quick, chicken",
			"ingredients": "8 chicken thighs\n1 lemon\n500 g baby potatoes\n2 tbsp olive oil\nFresh thyme",
			"steps":       "Toss everything with oil, salt and thyme on a tray.\nRoast at 220°C for 35 minutes until golden."},
		{"title": "Granola", "servings": "10", "prep_minutes": "10", "cook_minutes": "30", "tags": "breakfast",
			"ingredients": "300 g rolled oats\n100 g nuts\n60 ml maple syrup\n50 ml oil\nPinch of salt",
			"steps":       "Mix, spread on a tray, bake at 160°C for 30 minutes stirring once."},
	}
	for _, r := range recipes {
		c.post("/recipes", r)
	}

	// Share the Dinners folder with the Family group.
	c.nav("/groups")
	html = must(c.eval(`document.documentElement.outerHTML`))
	gm := regexp.MustCompile(`href="/groups/(\d+)">Family<`).FindStringSubmatch(html)
	c.post("/shares", map[string]string{"subject_type": "folder", "subject_id": folderIDs["Dinners"], "grantee_type": "group", "group": gm[1], "perm": "view"})

	// 4. Screenshots of the populated app.
	c.nav("/")
	c.shot("04-home")
	c.nav("/folders/" + folderIDs["Dinners"])
	must(c.eval(`document.querySelectorAll('details').forEach(d => d.open = true); 'ok'`))
	c.shot("05-folder-sharing")
	c.nav("/")
	html = must(c.eval(`document.documentElement.outerHTML`))
	c.nav("/folders/" + folderIDs["Italian"])
	html = must(c.eval(`document.documentElement.outerHTML`))
	rm := regexp.MustCompile(`href="/recipes/(\d+)"`).FindStringSubmatch(html)
	c.nav("/recipes/" + rm[1])
	c.shot("06-recipe")
	c.nav("/import")
	c.shot("07-import")
	pasted := "Miso Butter Mushrooms\n\nServes 2. Prep 5 min. Cook 15 min.\n\nIngredients\n- 400 g mixed mushrooms\n- 2 tbsp butter\n- 1 tbsp white miso\n- 1 clove garlic\n- Toast, to serve\n\nMethod\n1. Sear the mushrooms in a dry pan until browned.\n2. Add butter, miso and garlic; toss for two minutes.\n3. Pile onto toast.\n"
	must(c.eval(fmt.Sprintf(`(() => { const f=document.createElement('form'); f.method='post'; f.action='/import'; f.enctype='multipart/form-data';
		const t=document.createElement('textarea'); t.name='text'; t.value=%q; f.appendChild(t); document.body.appendChild(f); f.submit(); return 'ok'; })()`, pasted)))
	time.Sleep(300 * time.Millisecond)
	c.waitLoad()
	c.shot("08-import-review")
	c.nav("/groups/" + gm[1])
	c.shot("09-group")
	c.nav("/admin")
	c.shot("10-admin")
	c.nav("/search?q=chicken")
	c.shot("11-search")

	// 5. Log out and capture the sign-in page.
	c.post("/logout", nil)
	c.nav("/login")
	c.shot("12-login")
}
