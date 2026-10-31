package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/brett6320/recipe-manager/internal/auth"
	"github.com/brett6320/recipe-manager/internal/httpx"
)

// --- first-run setup ---

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	n, err := s.auth.UserCount(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup.html", pageData{Title: "Set up"})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.auth.UserCount(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n > 0 {
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	u, err := s.auth.CreateUser(r.Context(), r.FormValue("username"), r.FormValue("display_name"), true)
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "setup.html", pageData{Title: "Set up", Error: err.Error()})
		return
	}
	if err := s.login(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Account created. Now add a passkey or authenticator app.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// --- invite registration ---

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	ok, err := s.auth.InviteValid(r.Context(), code)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.render(w, r, http.StatusForbidden, "register.html", pageData{Title: "Register", Error: "This invite link is invalid or has expired."})
		return
	}
	s.render(w, r, http.StatusOK, "register.html", pageData{Title: "Register", Data: map[string]any{"Code": code}})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	ok, err := s.auth.InviteValid(r.Context(), code)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.failures.Fail("invite:" + httpx.ClientIP(r))
		s.render(w, r, http.StatusForbidden, "register.html", pageData{Title: "Register", Error: "This invite link is invalid or has expired."})
		return
	}
	u, err := s.auth.CreateUser(r.Context(), r.FormValue("username"), r.FormValue("display_name"), false)
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "register.html", pageData{Title: "Register", Error: err.Error(), Data: map[string]any{"Code": code}})
		return
	}
	if err := s.auth.RedeemInvite(r.Context(), code, u.ID); err != nil {
		_ = s.auth.DeleteUser(r.Context(), u.ID)
		s.render(w, r, http.StatusForbidden, "register.html", pageData{Title: "Register", Error: err.Error()})
		return
	}
	if err := s.login(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Account created. Now add a passkey or authenticator app.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// --- login ---

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	n, err := s.auth.UserCount(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login.html", pageData{Title: "Sign in"})
}

func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	code := r.FormValue("code")
	ipKey := "totp-ip:" + httpx.ClientIP(r)
	userKey := "totp-user:" + username
	fail := func(msg string) {
		s.failures.Fail(ipKey)
		s.failures.Fail(userKey)
		s.log.Warn("totp login failed", "user", username, "ip", httpx.ClientIP(r))
		// Constant-ish response time so user enumeration via timing is harder.
		time.Sleep(300 * time.Millisecond)
		s.render(w, r, http.StatusUnauthorized, "login.html", pageData{Title: "Sign in", Error: msg})
	}
	if s.failures.Locked(ipKey) || s.failures.Locked(userKey) {
		fail("Too many attempts. Try again later.")
		return
	}
	u, err := s.auth.UserByUsername(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			fail("Invalid username or code.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.auth.VerifyTOTP(r.Context(), s.keys, u, code, false); err != nil {
		fail("Invalid username or code.")
		return
	}
	s.failures.Reset(ipKey)
	s.failures.Reset(userKey)
	if err := s.login(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok := currentToken(r); tok != "" {
		_ = s.auth.DeleteSession(r.Context(), tok)
	}
	s.clearCookie(w, "session")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- WebAuthn JSON API ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type waPayload struct {
	Challenge  string          `json:"challenge"`
	Name       string          `json:"name,omitempty"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) handleWARegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.WebAuthnCredentials()))
	for _, c := range u.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sd, err := s.wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.challenges.Put(sd, u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": id, "options": opts})
}

func (s *Server) handleWARegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var p waPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	sd, uid, ok := s.challenges.Take(p.Challenge)
	if !ok || uid != u.ID {
		jsonError(w, http.StatusBadRequest, "challenge expired, try again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(p.Credential)))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid credential")
		return
	}
	cred, err := s.wa.CreateCredential(u, *sd, parsed)
	if err != nil {
		s.log.Warn("passkey registration failed", "user", u.Username, "err", err)
		jsonError(w, http.StatusBadRequest, "passkey could not be verified")
		return
	}
	if err := s.auth.AddPasskey(r.Context(), u.ID, p.Name, cred); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("passkey added", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleWALoginBegin(w http.ResponseWriter, r *http.Request) {
	opts, sd, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.challenges.Put(sd, 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": id, "options": opts})
}

func (s *Server) handleWALoginFinish(w http.ResponseWriter, r *http.Request) {
	ipKey := "wa-ip:" + httpx.ClientIP(r)
	if s.failures.Locked(ipKey) {
		jsonError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var p waPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	sd, _, ok := s.challenges.Take(p.Challenge)
	if !ok {
		jsonError(w, http.StatusBadRequest, "challenge expired, try again")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(p.Credential)))
	if err != nil {
		s.failures.Fail(ipKey)
		jsonError(w, http.StatusBadRequest, "invalid assertion")
		return
	}
	handler := func(rawID, handle []byte) (webauthn.User, error) {
		return s.auth.UserByHandle(r.Context(), handle)
	}
	user, cred, err := s.wa.ValidatePasskeyLogin(handler, *sd, parsed)
	if err != nil {
		s.failures.Fail(ipKey)
		s.log.Warn("passkey login failed", "ip", httpx.ClientIP(r), "err", err)
		jsonError(w, http.StatusUnauthorized, "passkey could not be verified")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey clone warning", "user", user.WebAuthnName())
		jsonError(w, http.StatusUnauthorized, "passkey rejected")
		return
	}
	u := user.(*auth.User)
	if err := s.auth.UpdatePasskey(r.Context(), cred); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.failures.Reset(ipKey)
	if err := s.login(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "redirect": "/"})
}

// --- security settings ---

type securityData struct {
	Passkeys    []auth.Passkey
	TOTPEnabled bool
	Enrolment   *auth.TOTPEnrolment
	Sessions    int
	Complete    bool
}

func (s *Server) securityData(r *http.Request, u *auth.User) (*securityData, error) {
	pks, err := s.auth.Passkeys(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	_, totp, err := s.auth.MethodCount(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	n, err := s.auth.SessionCount(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	return &securityData{Passkeys: pks, TOTPEnabled: totp, Sessions: n, Complete: len(pks) > 0 || totp}, nil
}

func (s *Server) handleSecurityPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.securityData(r, currentUser(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "security.html", pageData{Title: "Security", Data: d})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	pk, totp, err := s.auth.MethodCount(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if pk <= 1 && !totp {
		s.setFlash(w, "You cannot remove your only login method.")
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	if err := s.auth.DeletePasskey(r.Context(), u.ID, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Passkey removed.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	enr, err := s.auth.BeginTOTP(r.Context(), s.keys, "Recipes ("+s.cfg.RPID+")", u)
	if err != nil {
		s.setFlash(w, err.Error())
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	d, err := s.securityData(r, u)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Enrolment = enr
	s.render(w, r, http.StatusOK, "security.html", pageData{Title: "Security", Data: d})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if err := s.auth.VerifyTOTP(r.Context(), s.keys, u, r.FormValue("code"), true); err != nil {
		s.setFlash(w, "Could not confirm code: "+err.Error()+" Start again to get a new QR code.")
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	s.log.Info("totp enabled", "user", u.Username)
	s.setFlash(w, "Authenticator app enabled.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (s *Server) handleTOTPRemove(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	pk, _, err := s.auth.MethodCount(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if pk == 0 {
		s.setFlash(w, "Add a passkey before removing your authenticator app.")
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	if err := s.auth.DeleteTOTP(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Authenticator app removed.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if err := s.auth.DeleteUserSessions(r.Context(), u.ID, currentToken(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setFlash(w, "Signed out everywhere else.")
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// --- admin ---

type adminUser struct {
	*auth.User
	Passkeys int
	TOTP     bool
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]adminUser, 0, len(users))
	for _, u := range users {
		pk, totp, err := s.auth.MethodCount(r.Context(), u.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		out = append(out, adminUser{User: u, Passkeys: pk, TOTP: totp})
	}
	pending, err := s.auth.PendingInvites(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin.html", pageData{Title: "Admin", Data: map[string]any{
		"Users":   out,
		"Pending": pending,
		"Invite":  s.takeFlashInvite(w, r),
	}})
}

// Invite links are shown exactly once via a short-lived cookie so they never
// land in server logs or referrers.
func (s *Server) takeFlashInvite(w http.ResponseWriter, r *http.Request) string {
	v := s.readCookie(r, "invite")
	if v == "" {
		return ""
	}
	s.clearCookie(w, "invite")
	return s.cfg.Origin + "/register?code=" + v
}

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	code, err := s.auth.CreateInvite(r.Context(), currentUser(r).ID, 48*time.Hour)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setCookie(w, "invite", code, 60)
	s.setFlash(w, "Invite created. The link below is shown once and expires in 48 hours.")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if id == me.ID {
		s.setFlash(w, "You cannot delete your own account.")
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if err := s.auth.DeleteUser(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("user deleted", "by", me.Username, "id", id)
	s.setFlash(w, "User deleted.")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminToggleAdmin(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	target, err := s.auth.UserByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if target.IsAdmin {
		n, err := s.auth.AdminCount(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if n <= 1 {
			s.setFlash(w, "There must be at least one admin.")
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
	}
	if err := s.auth.SetAdmin(r.Context(), id, !target.IsAdmin); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("admin toggled", "by", me.Username, "user", target.Username, "admin", !target.IsAdmin)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
