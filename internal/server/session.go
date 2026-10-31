package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/brett6320/recipe-manager/internal/auth"
	"github.com/brett6320/recipe-manager/internal/httpx"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxToken
)

func (s *Server) cookieName(base string) string {
	if s.cfg.DevInsecure {
		return base
	}
	return "__Host-" + base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is only relaxed under RM_DEV_INSECURE for local http development
		Name:     s.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !s.cfg.DevInsecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	s.setCookie(w, name, "", -1)
}

func (s *Server) readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return c.Value
}

// setFlash stores a one-shot message in a short-lived cookie.
func (s *Server) setFlash(w http.ResponseWriter, msg string) {
	s.setCookie(w, "flash", url.QueryEscape(msg), 60)
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) string {
	v := s.readCookie(r, "flash")
	if v == "" {
		return ""
	}
	s.clearCookie(w, "flash")
	msg, _ := url.QueryUnescape(v)
	return msg
}

func currentUser(r *http.Request) *auth.User {
	u, _ := r.Context().Value(ctxUser).(*auth.User)
	return u
}

func currentToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxToken).(string)
	return t
}

// withSession attaches the user when a valid session cookie is present.
func (s *Server) withSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := s.readCookie(r, "session")
		if tok == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := s.auth.SessionByToken(r.Context(), tok, s.cfg.SessionIdle)
		if err != nil {
			if !errors.Is(err, auth.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
			s.clearCookie(w, "session")
			next.ServeHTTP(w, r)
			return
		}
		u, err := s.auth.UserByID(r.Context(), sess.UserID)
		if err != nil {
			s.clearCookie(w, "session")
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxToken, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireUser enforces login. When enrolled is true the user must also have
// at least one login method, otherwise they are sent to /security.
func (s *Server) requireUser(next http.HandlerFunc, enrolled bool) http.Handler {
	return s.withSession(func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if u == nil {
			if isAPI(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if enrolled {
			pk, totp, err := s.auth.MethodCount(r.Context(), u.ID)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			if pk == 0 && !totp {
				s.setFlash(w, "Add a passkey or authenticator app to finish setting up your account.")
				http.Redirect(w, r, "/security", http.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		if !currentUser(r).IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}, true)
}

func isAPI(r *http.Request) bool {
	return len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/"
}

// login establishes a session for u and rotates the cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request, u *auth.User) error {
	if old := s.readCookie(r, "session"); old != "" {
		_ = s.auth.DeleteSession(r.Context(), old)
	}
	tok, err := s.auth.CreateSession(r.Context(), u.ID, s.cfg.SessionTTL, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		return err
	}
	s.setCookie(w, "session", tok, int(s.cfg.SessionTTL/time.Second))
	s.log.Info("login", "user", u.Username, "ip", httpx.ClientIP(r))
	return nil
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}
