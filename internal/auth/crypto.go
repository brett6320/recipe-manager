package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Keyring holds the instance secret used to encrypt TOTP seeds at rest.
type Keyring struct {
	aead cipher.AEAD
}

// LoadOrCreateKey reads dataDir/secret.key or generates a fresh 32-byte key
// with 0600 permissions.
func LoadOrCreateKey(dataDir string) (*Keyring, error) {
	p := filepath.Join(dataDir, "secret.key")
	key, err := os.ReadFile(p) //nolint:gosec // path is derived from the operator-configured data dir
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, key, 0o600); err != nil {
			return nil, fmt.Errorf("write secret key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("secret.key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Keyring{aead: aead}, nil
}

// Seal encrypts plaintext bound to the given context string.
func (k *Keyring) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, k.aead.Seal(nil, nonce, plaintext, []byte(context))...), nil
}

// Open decrypts data produced by Seal.
func (k *Keyring) Open(data []byte, context string) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return k.aead.Open(nil, data[:ns], data[ns:], []byte(context))
}

// RandomToken returns n random bytes encoded as URL-safe base64.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// HashToken returns the SHA-256 digest of a token for storage/lookup.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// ConstantTimeEqual compares two byte slices in constant time.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
