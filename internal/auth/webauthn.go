package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// NewWebAuthn configures the relying party.
func NewWebAuthn(rpID, origin, displayName string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
		},
	})
}

// ChallengeStore keeps in-flight WebAuthn ceremonies in memory.
type ChallengeStore struct {
	mu sync.Mutex
	m  map[string]challenge
}

type challenge struct {
	data   webauthn.SessionData
	userID int64
	exp    time.Time
}

// NewChallengeStore returns an empty store with background expiry.
func NewChallengeStore() *ChallengeStore {
	c := &ChallengeStore{m: map[string]challenge{}}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.m {
				if now.After(v.exp) {
					delete(c.m, k)
				}
			}
			c.mu.Unlock()
		}
	}()
	return c
}

// Put stores session data and returns an opaque id.
func (c *ChallengeStore) Put(sd *webauthn.SessionData, userID int64) (string, error) {
	id, err := RandomToken(24)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 10000 {
		return "", errors.New("too many pending challenges")
	}
	c.m[id] = challenge{data: *sd, userID: userID, exp: time.Now().Add(3 * time.Minute)}
	return id, nil
}

// Take removes and returns the session data for id.
func (c *ChallengeStore) Take(id string) (*webauthn.SessionData, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	if !ok {
		return nil, 0, false
	}
	delete(c.m, id)
	if time.Now().After(v.exp) {
		return nil, 0, false
	}
	return &v.data, v.userID, true
}
