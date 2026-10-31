package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image/png"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpPeriod = 30

// TOTPEnrolment is returned when a user starts TOTP setup.
type TOTPEnrolment struct {
	Secret  string // base32, show once
	QRData  string // data: URI PNG
	Account string
}

// BeginTOTP generates a new secret, encrypts it and stores it unconfirmed.
func (s *Store) BeginTOTP(ctx context.Context, kr *Keyring, issuer string, u *User) (*TOTPEnrolment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: u.Username,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // widest authenticator compatibility
		SecretSize:  20,
	})
	if err != nil {
		return nil, err
	}
	enc, err := kr.Seal([]byte(key.Secret()), totpContext(u))
	if err != nil {
		return nil, err
	}
	if err := s.SetPendingTOTP(ctx, u.ID, enc); err != nil {
		return nil, err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return &TOTPEnrolment{
		Secret:  key.Secret(),
		QRData:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Account: u.Username,
	}, nil
}

func totpContext(u *User) string { return "totp:" + string(u.Handle) }

// totpCounter returns the time step for t.
func totpCounter(t time.Time) int64 { return t.Unix() / totpPeriod }

// VerifyTOTP checks a code against the user's secret. It accepts +/- one
// step of skew and rejects any step at or before the last accepted one so a
// captured code cannot be replayed. When confirm is true the pending secret
// is activated on success.
func (s *Store) VerifyTOTP(ctx context.Context, kr *Keyring, u *User, code string, confirm bool) error {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return errors.New("code must be 6 digits")
	}
	enc, confirmed, last, err := s.TOTPRecord(ctx, u.ID)
	if err != nil {
		return errors.New("authenticator app not set up")
	}
	if confirm == confirmed {
		if confirm {
			return errors.New("TOTP already confirmed")
		}
		return errors.New("authenticator app not set up")
	}
	secret, err := kr.Open(enc, totpContext(u))
	if err != nil {
		return err
	}
	now := time.Now()
	for _, skew := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(skew*totpPeriod) * time.Second)
		ok, _ := totp.ValidateCustom(code, string(secret), t, totp.ValidateOpts{Period: totpPeriod, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if !ok {
			continue
		}
		c := totpCounter(t)
		if c <= last {
			return errors.New("code already used")
		}
		if confirm {
			return s.ConfirmTOTP(ctx, u.ID, c)
		}
		adv, err := s.AdvanceTOTPCounter(ctx, u.ID, c)
		if err != nil {
			return err
		}
		if !adv {
			return errors.New("code already used")
		}
		return nil
	}
	return errors.New("invalid code")
}

// FailureTracker locks a key after too many failures within a window.
type FailureTracker struct {
	mu     sync.Mutex
	m      map[string]*failure
	max    int
	window time.Duration
	lock   time.Duration
}

type failure struct {
	count int
	first time.Time
	until time.Time
}

// NewFailureTracker allows max failures per window before locking for lock.
func NewFailureTracker(max int, window, lock time.Duration) *FailureTracker {
	f := &FailureTracker{m: map[string]*failure{}, max: max, window: window, lock: lock}
	go f.gc()
	return f
}

func (f *FailureTracker) gc() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		f.mu.Lock()
		now := time.Now()
		for k, v := range f.m {
			if now.After(v.until) && now.Sub(v.first) > f.window {
				delete(f.m, k)
			}
		}
		f.mu.Unlock()
	}
}

// Locked reports whether key is currently locked out.
func (f *FailureTracker) Locked(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	return ok && time.Now().Before(v.until)
}

// Fail records a failure for key.
func (f *FailureTracker) Fail(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	v, ok := f.m[key]
	if !ok || now.Sub(v.first) > f.window {
		v = &failure{first: now}
		f.m[key] = v
	}
	v.count++
	if v.count >= f.max {
		v.until = now.Add(f.lock)
	}
}

// Reset clears failures for key after a success.
func (f *FailureTracker) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
}
