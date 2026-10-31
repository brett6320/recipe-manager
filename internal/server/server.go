// Package server wires HTTP routes, templates and middleware together.
package server

import (
	"context"
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/brett6320/recipe-manager/internal/auth"
	"github.com/brett6320/recipe-manager/internal/config"
	"github.com/brett6320/recipe-manager/internal/httpx"
	"github.com/brett6320/recipe-manager/internal/recipes"
	"github.com/brett6320/recipe-manager/web"
)

// Server holds shared dependencies for handlers.
type Server struct {
	cfg        *config.Config
	db         *sql.DB
	log        *slog.Logger
	tmpl       map[string]*template.Template
	auth       *auth.Store
	recipes    *recipes.Store
	keys       *auth.Keyring
	wa         *webauthn.WebAuthn
	challenges *auth.ChallengeStore
	failures   *auth.FailureTracker
}

// New builds the Server and parses templates.
func New(cfg *config.Config, db *sql.DB, log *slog.Logger) (*Server, error) {
	keys, err := auth.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	wa, err := auth.NewWebAuthn(cfg.RPID, cfg.Origin, "Recipes")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		db:         db,
		log:        log,
		auth:       auth.NewStore(db),
		recipes:    recipes.NewStore(db),
		keys:       keys,
		wa:         wa,
		challenges: auth.NewChallengeStore(),
		failures:   auth.NewFailureTracker(5, 10*time.Minute, 15*time.Minute),
	}
	if err := s.parseTemplates(web.Templates); err != nil {
		return nil, err
	}
	go s.cleanupLoop()
	return s, nil
}

func (s *Server) cleanupLoop() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.auth.Cleanup(ctx); err != nil {
			s.log.Error("cleanup", "err", err)
		}
		cancel()
	}
}

func (s *Server) parseTemplates(fsys embed.FS) error {
	funcs := template.FuncMap{
		"join": strings.Join,
		"deref": func(p *int64) int64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"minutes": func(p *int) string {
			if p == nil || *p == 0 {
				return ""
			}
			return strconv.Itoa(*p) + " min"
		},
		"paragraphs": func(s string) []string { return strings.Split(s, "\n\n") },
		"dict": func(kv ...any) map[string]any {
			m := make(map[string]any, len(kv)/2)
			for i := 0; i+1 < len(kv); i += 2 {
				if k, ok := kv[i].(string); ok {
					m[k] = kv[i+1]
				}
			}
			return m
		},
		"now": time.Now,
		"date": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"datep": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
	}
	pages, err := fs.Glob(fsys, "templates/pages/*.html")
	if err != nil {
		return err
	}
	s.tmpl = map[string]*template.Template{}
	for _, p := range pages {
		t, err := template.New("base.html").Funcs(funcs).ParseFS(fsys, "templates/base.html", "templates/partials/*.html", p)
		if err != nil {
			return err
		}
		s.tmpl[path.Base(p)] = t
	}
	return nil
}

// Handler returns the fully wrapped root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(web.Static, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	// Authentication endpoints get a stricter per-IP limiter.
	authLimit := httpx.NewLimiter(1, 15)
	pub := func(h http.HandlerFunc) http.Handler { return authLimit.Middleware(s.withSession(h)) }

	mux.Handle("GET /setup", pub(s.handleSetupPage))
	mux.Handle("POST /setup", pub(s.handleSetup))
	mux.Handle("GET /login", pub(s.handleLoginPage))
	mux.Handle("POST /login/totp", pub(s.handleLoginTOTP))
	mux.Handle("POST /api/webauthn/login/begin", pub(s.handleWALoginBegin))
	mux.Handle("POST /api/webauthn/login/finish", pub(s.handleWALoginFinish))
	mux.Handle("GET /register", pub(s.handleRegisterPage))
	mux.Handle("POST /register", pub(s.handleRegister))
	mux.Handle("POST /logout", s.withSession(s.handleLogout))

	// Security settings are reachable even before enrolment completes.
	sec := func(h http.HandlerFunc) http.Handler { return s.requireUser(h, false) }
	mux.Handle("GET /security", sec(s.handleSecurityPage))
	mux.Handle("POST /api/webauthn/register/begin", sec(s.handleWARegisterBegin))
	mux.Handle("POST /api/webauthn/register/finish", sec(s.handleWARegisterFinish))
	mux.Handle("POST /security/passkeys/{id}/delete", sec(s.handlePasskeyDelete))
	mux.Handle("POST /security/totp/begin", sec(s.handleTOTPBegin))
	mux.Handle("POST /security/totp/confirm", sec(s.handleTOTPConfirm))
	mux.Handle("POST /security/totp/remove", sec(s.handleTOTPRemove))
	mux.Handle("POST /security/sessions/revoke", sec(s.handleRevokeSessions))

	// Everything else requires a fully enrolled account.
	app := func(h http.HandlerFunc) http.Handler { return s.requireUser(h, true) }
	mux.Handle("GET /{$}", app(s.handleIndex))
	mux.Handle("GET /search", app(s.handleSearch))
	mux.Handle("GET /export.json", app(s.handleExportAll))

	mux.Handle("GET /folders/{id}", app(s.handleFolder))
	mux.Handle("POST /folders", app(s.handleFolderCreate))
	mux.Handle("POST /folders/{id}/rename", app(s.handleFolderRename))
	mux.Handle("POST /folders/{id}/move", app(s.handleFolderMove))
	mux.Handle("POST /folders/{id}/delete", app(s.handleFolderDelete))

	mux.Handle("GET /recipes/new", app(s.handleRecipeNew))
	mux.Handle("POST /recipes", app(s.handleRecipeCreate))
	mux.Handle("GET /recipes/{id}", app(s.handleRecipeView))
	mux.Handle("GET /recipes/{id}/export.json", app(s.handleRecipeExport))
	mux.Handle("GET /recipes/{id}/edit", app(s.handleRecipeEdit))
	mux.Handle("POST /recipes/{id}", app(s.handleRecipeUpdate))
	mux.Handle("POST /recipes/{id}/move", app(s.handleRecipeMove))
	mux.Handle("POST /recipes/{id}/delete", app(s.handleRecipeDelete))

	mux.Handle("POST /shares", app(s.handleShareAdd))
	mux.Handle("POST /shares/{id}/delete", app(s.handleShareRemove))

	mux.Handle("GET /groups", app(s.handleGroups))
	mux.Handle("POST /groups", app(s.handleGroupCreate))
	mux.Handle("GET /groups/{id}", app(s.handleGroupView))
	mux.Handle("POST /groups/{id}/members", app(s.handleGroupAddMember))
	mux.Handle("POST /groups/{id}/members/{uid}/remove", app(s.handleGroupRemoveMember))
	mux.Handle("POST /groups/{id}/delete", app(s.handleGroupDelete))

	admin := func(h http.HandlerFunc) http.Handler { return s.requireAdmin(h) }
	mux.Handle("GET /admin", admin(s.handleAdminPage))
	mux.Handle("POST /admin/invites", admin(s.handleAdminInvite))
	mux.Handle("POST /admin/users/{id}/delete", admin(s.handleAdminDeleteUser))
	mux.Handle("POST /admin/users/{id}/admin", admin(s.handleAdminToggleAdmin))

	global := httpx.NewLimiter(50, 100)

	return httpx.Chain(mux,
		httpx.Recover(s.log),
		httpx.RealIP(s.cfg.TrustedProxy, s.cfg.RequireProxy),
		httpx.Logging(s.log),
		httpx.SecurityHeaders(!s.cfg.DevInsecure),
		global.Middleware,
		httpx.OriginCheck(s.cfg.Origin),
		httpx.MaxBody(1<<20),
	)
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Title string
	Flash string
	Error string
	User  *auth.User
	Data  any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, d pageData) {
	t, ok := s.tmpl[name]
	if !ok {
		s.log.Error("missing template", "name", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if d.User == nil {
		d.User = currentUser(r)
	}
	if d.Flash == "" {
		d.Flash = s.takeFlash(w, r)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base.html", d); err != nil {
		s.log.Error("render", "name", name, "err", err)
	}
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("handler error", "path", r.URL.Path, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
