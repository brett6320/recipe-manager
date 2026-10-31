// Package auth implements users, sessions, passkeys and TOTP.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// User is an account. It satisfies webauthn.User.
type User struct {
	ID          int64
	Handle      []byte
	Username    string
	DisplayName string
	IsAdmin     bool
	CreatedAt   time.Time
	creds       []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.Handle }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// Passkey is a stored WebAuthn credential with display metadata.
type Passkey struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Cred       webauthn.Credential
}

// Store persists auth state.
type Store struct {
	db *sql.DB
}

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

// ValidateUsername normalises and checks a username.
func ValidateUsername(u string) (string, error) {
	u = strings.ToLower(strings.TrimSpace(u))
	if !usernameRe.MatchString(u) {
		return "", errors.New("username must be 2-32 chars: lowercase letters, digits, . _ -")
	}
	return u, nil
}

// UserCount returns the number of accounts.
func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a user with a fresh random WebAuthn handle.
func (s *Store) CreateUser(ctx context.Context, username, display string, admin bool) (*User, error) {
	username, err := ValidateUsername(username)
	if err != nil {
		return nil, err
	}
	display = strings.TrimSpace(display)
	if display == "" {
		display = username
	}
	if len(display) > 64 {
		return nil, errors.New("display name too long")
	}
	handle, err := RandomBytes(64)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (handle, username, display_name, is_admin) VALUES (?,?,?,?)`, handle, username, display, admin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, errors.New("username already taken")
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

func (s *Store) scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created string
	if err := row.Scan(&u.ID, &u.Handle, &u.Username, &u.DisplayName, &u.IsAdmin, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return &u, nil
}

const userCols = `id, handle, username, display_name, is_admin, created_at`

// UserByID loads a user and their credentials.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	u, err := s.scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return u, s.loadCreds(ctx, u)
}

// UserByUsername loads a user by (case-insensitive) username.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := s.scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(username))))
	if err != nil {
		return nil, err
	}
	return u, s.loadCreds(ctx, u)
}

// UserByHandle loads a user by WebAuthn user handle.
func (s *Store) UserByHandle(ctx context.Context, handle []byte) (*User, error) {
	u, err := s.scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE handle = ?`, handle))
	if err != nil {
		return nil, err
	}
	return u, s.loadCreds(ctx, u)
}

// ListUsers returns all users (without credentials).
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes an account and everything owned by it.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// AdminCount returns the number of admins.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&n)
	return n, err
}

func (s *Store) loadCreds(ctx context.Context, u *User) error {
	pks, err := s.Passkeys(ctx, u.ID)
	if err != nil {
		return err
	}
	u.creds = u.creds[:0]
	for _, pk := range pks {
		u.creds = append(u.creds, pk.Cred)
	}
	return nil
}

// Passkeys lists a user's credentials.
func (s *Store) Passkeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, data, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Passkey
	for rows.Next() {
		var pk Passkey
		var data []byte
		var created string
		var last sql.NullString
		if err := rows.Scan(&pk.ID, &pk.Name, &data, &created, &last); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &pk.Cred); err != nil {
			return nil, fmt.Errorf("decode credential %d: %w", pk.ID, err)
		}
		pk.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if last.Valid {
			t, _ := time.Parse(time.RFC3339Nano, last.String)
			pk.LastUsedAt = &t
		}
		out = append(out, pk)
	}
	return out, rows.Err()
}

// AddPasskey stores a new credential.
func (s *Store) AddPasskey(ctx context.Context, userID int64, name string, c *webauthn.Credential) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO webauthn_credentials (user_id, credential_id, name, data) VALUES (?,?,?,?)`, userID, c.ID, name, data)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("this passkey is already registered")
	}
	return err
}

// UpdatePasskey persists the post-login credential state (sign count, flags).
func (s *Store) UpdatePasskey(ctx context.Context, c *webauthn.Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET data = ?, last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE credential_id = ?`, data, c.ID)
	return err
}

// DeletePasskey removes a credential owned by userID.
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// MethodCount returns how many usable second factors a user has
// (confirmed TOTP counts as one, each passkey as one).
func (s *Store) MethodCount(ctx context.Context, userID int64) (passkeys int, totp bool, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&passkeys); err != nil {
		return
	}
	var n int
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp WHERE user_id = ? AND confirmed = 1`, userID).Scan(&n); err != nil {
		return
	}
	totp = n > 0
	return
}

// --- TOTP ---

// SetPendingTOTP stores an unconfirmed encrypted secret, replacing any
// unconfirmed one. A confirmed secret is never silently replaced.
func (s *Store) SetPendingTOTP(ctx context.Context, userID int64, enc []byte) error {
	var confirmed int
	err := s.db.QueryRowContext(ctx, `SELECT confirmed FROM totp WHERE user_id = ?`, userID).Scan(&confirmed)
	if err == nil && confirmed == 1 {
		return errors.New("TOTP already enabled; remove it first")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO totp (user_id, secret_enc, confirmed, last_counter) VALUES (?,?,0,0)
		ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed = 0, last_counter = 0, created_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`, userID, enc)
	return err
}

// TOTPRecord returns the encrypted secret and state.
func (s *Store) TOTPRecord(ctx context.Context, userID int64) (enc []byte, confirmed bool, lastCounter int64, err error) {
	var c int
	err = s.db.QueryRowContext(ctx, `SELECT secret_enc, confirmed, last_counter FROM totp WHERE user_id = ?`, userID).Scan(&enc, &c, &lastCounter)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	confirmed = c == 1
	return
}

// ConfirmTOTP marks the secret as confirmed and records the counter used.
func (s *Store) ConfirmTOTP(ctx context.Context, userID, counter int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE totp SET confirmed = 1, last_counter = ? WHERE user_id = ?`, counter, userID)
	return err
}

// AdvanceTOTPCounter records an accepted time step, guarding replay. It
// returns false if counter is not strictly greater than the stored one.
func (s *Store) AdvanceTOTPCounter(ctx context.Context, userID, counter int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE totp SET last_counter = ? WHERE user_id = ? AND confirmed = 1 AND last_counter < ?`, counter, userID, counter)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteTOTP removes the TOTP enrolment.
func (s *Store) DeleteTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp WHERE user_id = ?`, userID)
	return err
}

// --- Sessions ---

// Session is a logged-in browser session.
type Session struct {
	UserID    int64
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// CreateSession stores a session and returns the raw token for the cookie.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration, ip, ua string) (string, error) {
	tok, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	if len(ua) > 256 {
		ua = ua[:256]
	}
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES (?,?,?,?,?)`, HashToken(tok), userID, exp, ip, ua)
	return tok, err
}

// SessionByToken resolves a token to a live session, enforcing absolute
// expiry and idle timeout, and touches last_seen.
func (s *Store) SessionByToken(ctx context.Context, tok string, idle time.Duration) (*Session, error) {
	h := HashToken(tok)
	var sess Session
	var created, last, exp string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE token_hash = ?`, h).
		Scan(&sess.UserID, &created, &last, &exp, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	sess.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
	sess.ExpiresAt, _ = time.Parse(time.RFC3339Nano, exp)
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > idle {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, h)
		return nil, ErrNotFound
	}
	if now.Sub(sess.LastSeen) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE token_hash = ?`, h)
	}
	return &sess, nil
}

// DeleteSession revokes one session.
func (s *Store) DeleteSession(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, HashToken(tok))
	return err
}

// DeleteUserSessions revokes all sessions for a user, optionally keeping one.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keepTok string) error {
	if keepTok == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, userID, HashToken(keepTok))
	return err
}

// SessionCount returns active sessions for a user.
func (s *Store) SessionCount(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')`, userID).Scan(&n)
	return n, err
}

// Cleanup removes expired sessions/invites and abandoned accounts that
// never enrolled a login method.
func (s *Store) Cleanup(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE used_at IS NULL AND expires_at < ?`, now); err != nil {
		return err
	}
	cutoff := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE created_at < ?
		AND id NOT IN (SELECT user_id FROM webauthn_credentials)
		AND id NOT IN (SELECT user_id FROM totp WHERE confirmed = 1)`, cutoff)
	return err
}

// --- Invites ---

// Invite is a one-time registration code.
type Invite struct {
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    *int64
}

// CreateInvite returns a raw invite code valid for ttl.
func (s *Store) CreateInvite(ctx context.Context, by int64, ttl time.Duration) (string, error) {
	code, err := RandomToken(24)
	if err != nil {
		return "", err
	}
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites (code_hash, created_by, expires_at) VALUES (?,?,?)`, HashToken(code), by, exp)
	return code, err
}

// RedeemInvite atomically consumes a valid code for the new user.
func (s *Store) RedeemInvite(ctx context.Context, code string, newUser int64) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `UPDATE invites SET used_by = ?, used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`, newUser, now, HashToken(code), now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("invalid or expired invite")
	}
	return nil
}

// InviteValid reports whether a code can still be redeemed.
func (s *Store) InviteValid(ctx context.Context, code string) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`, HashToken(code), now).Scan(&n)
	return n == 1, err
}

// PendingInvites counts unused, unexpired invites.
func (s *Store) PendingInvites(ctx context.Context) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE used_at IS NULL AND expires_at > ?`, now).Scan(&n)
	return n, err
}

// SetAdmin changes a user's admin flag.
func (s *Store) SetAdmin(ctx context.Context, id int64, admin bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET is_admin = ? WHERE id = ?`, admin, id)
	return err
}
