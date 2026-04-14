// Package secretenc provides symmetric encryption for secrets stored in the database.
// The only supported algorithm is AES-256-GCM with a random 12-byte nonce.
// Wire format: [12 bytes nonce][ciphertext+16 bytes auth tag].
package secretenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

// KeyProvider encrypts and decrypts secret bytes.
// Implementations must be safe for concurrent use.
type KeyProvider interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// aesGCMProvider is the production AES-256-GCM implementation.
type aesGCMProvider struct {
	key []byte // exactly 32 bytes
}

func (p *aesGCMProvider) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("secretenc: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretenc: new GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretenc: generate nonce: %w", err)
	}
	// Seal appends ciphertext+tag after nonce.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (p *aesGCMProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("secretenc: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretenc: new GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("secretenc: ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("secretenc: decrypt: %w", err)
	}
	return plain, nil
}

// aes.NewCipher is called per-operation to keep aesGCMProvider free of shared
// mutable state (cipher.Block is not goroutine-safe). For the expected low call
// rate (CA key storage) this overhead is negligible.

// NewEnvKeyProvider reads a base64-encoded 32-byte key from the named environment variable.
func NewEnvKeyProvider(envVar string) (KeyProvider, error) {
	val := os.Getenv(envVar)
	if val == "" {
		return nil, fmt.Errorf("secretenc: env var %q is not set", envVar)
	}
	key, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("secretenc: decode key from %q: %w", envVar, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secretenc: key must be 32 bytes, got %d", len(key))
	}
	return &aesGCMProvider{key: key}, nil
}

// NewFileKeyProvider reads a raw 32-byte key from path.
// Returns an error if file permissions are more permissive than 0600
// (group or world read/write bits set) to prevent accidental key exposure.
func NewFileKeyProvider(path string) (KeyProvider, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secretenc: stat key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secretenc: key file %q has permissions %v; must be 0600 or more restrictive (no group/world bits)", path, info.Mode().Perm())
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secretenc: read key file: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secretenc: key file must be exactly 32 bytes, got %d", len(key))
	}
	return &aesGCMProvider{key: key}, nil
}

// noOpProvider returns plaintext unchanged — for dev/test only.
type noOpProvider struct{}

func (noOpProvider) Encrypt(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	copy(out, p)
	return out, nil
}
func (noOpProvider) Decrypt(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	copy(out, p)
	return out, nil
}

// noOpAllowedEnvVar is the environment variable that must be set to the literal
// value "yes" to allow the no-op (plaintext) key provider in production.
// This prevents accidental use of the no-op provider without explicit opt-in.
const noOpAllowedEnvVar = "NB_SECRET_ENCRYPTION_NOOP_ALLOWED"

// NewNoOpKeyProvider returns an identity provider (no encryption).
// Logs a WARNING at construction time.
//
// In non-test binaries, the caller must set the environment variable
// NB_SECRET_ENCRYPTION_NOOP_ALLOWED=yes to opt in to plaintext storage.
// Without it, the function panics to prevent accidental production use.
func NewNoOpKeyProvider() KeyProvider {
	if !testing.Testing() && os.Getenv(noOpAllowedEnvVar) != "yes" {
		panic("secretenc: SecretEncryption not configured and " + noOpAllowedEnvVar + "!=yes — " +
			"refusing to start with plaintext CA key storage. Set SecretEncryption in " +
			"management.json or set " + noOpAllowedEnvVar + "=yes to explicitly allow plaintext storage.")
	}
	log.Warn("secretenc: SecretEncryption not configured — CA private keys and integration " +
		"credentials are stored in plaintext. Configure SecretEncryption in management.json " +
		"before production deployment.")
	return noOpProvider{}
}
