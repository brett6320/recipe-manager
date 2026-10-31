// Package server wires HTTP routes, templates and middleware together.
package server

import (
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/brett6320/recipe-manager/internal/config"
	"github.com/brett6320/recipe-manager/internal/httpx"
	"github.com/brett6320/recipe-manager/web"
)

// Server holds shared dependencies for handlers.
type Server struct {
	cfg  *config.Config
	db   *sql.DB
	log  *slog.Logger
	tmpl map[string]*template.Template
}

// New builds the Server and parses templates.
func New(cfg *config.Config, db *sql.DB, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, db: db, log: log}
	if err := s.parseTemplates(web.Templates); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) parseTemplates(fsys embed.FS) error {
	funcs := template.FuncMap{
		"join": strings.Join,
		"now":  time.Now,
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
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /{$}", s.handleIndex)

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
	Data  any
}

func (s *Server) render(w http.ResponseWriter, status int, name string, d pageData) {
	t, ok := s.tmpl[name]
	if !ok {
		s.log.Error("missing template", "name", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base.html", d); err != nil {
		s.log.Error("render", "name", name, "err", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "index.html", pageData{Title: "Recipes"})
}
