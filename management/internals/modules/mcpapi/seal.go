package mcpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvOAuthKey, when set, is the secret the broker seals codes and tokens with, in place of
// the datastore encryption key. Changing it signs every MCP client out at once. Instances
// serving the same domain must share it.
const EnvOAuthKey = "NB_MCP_OAUTH_KEY"

// purpose separates the kinds of sealed values, so a client id can never be replayed as a
// token, nor a refresh token as an access token.
type purpose string

const (
	purposeClient  purpose = "client"
	purposeConsent purpose = "consent"
	purposeLogin   purpose = "login"
	purposeCode    purpose = "code"
	purposeAccess  purpose = "access"
	purposeRefresh purpose = "refresh"
)

var errUnsealable = errors.New("value is not valid")

// sealer encrypts small JSON payloads into opaque strings with AES-GCM. Everything the
// broker hands out is sealed, which keeps the broker stateless: any instance holding the
// same secret can verify any value, and nothing needs a database row.
type sealer struct {
	aead cipher.AEAD
}

func newSealer(secret []byte) (*sealer, error) {
	if len(secret) == 0 {
		return nil, errors.New("empty sealing secret")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, "netbird-mcp-oauth-v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(p purpose, prefix string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(p))
	return prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *sealer) open(p purpose, prefix, value string, v any) error {
	raw, ok := strings.CutPrefix(value, prefix)
	if !ok {
		return errUnsealable
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(data) < s.aead.NonceSize() {
		return errUnsealable
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte(p))
	if err != nil {
		return errUnsealable
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return errUnsealable
	}
	return nil
}

// Secrets are the keys the broker seals with. Tokens seals codes, tokens and the browser
// state of a login; Registrations seals client ids. They differ so that changing
// NB_MCP_OAUTH_KEY signs every client out without unregistering it: a client id carries no
// authority, and a client that keeps its id can always sign in again.
type Secrets struct {
	Tokens        []byte
	Registrations []byte
}

// minOAuthKeyLength is the shortest NB_MCP_OAUTH_KEY accepted. HKDF does not stretch its
// input, so a short value would leave the token key open to offline guessing.
const minOAuthKeyLength = 32

// ResolveSecrets picks the broker's keys. Tokens use NB_MCP_OAUTH_KEY when set, else the
// datastore encryption key; registrations use the datastore key when there is one. Without
// either a random key is generated, which only works for a single instance and invalidates
// every MCP login and registration on restart. A NB_MCP_OAUTH_KEY shorter than 32 bytes is
// an error rather than a reason to fall back: falling back would revive the tokens the
// operator meant to revoke by setting it.
func ResolveSecrets(dataStoreKey string) (Secrets, error) {
	oauthKey := os.Getenv(EnvOAuthKey)
	if oauthKey != "" && len(oauthKey) < minOAuthKeyLength {
		return Secrets{}, fmt.Errorf("%s must be at least %d bytes, generate one with openssl rand -base64 32", EnvOAuthKey, minOAuthKeyLength)
	}
	switch {
	case oauthKey != "" && dataStoreKey != "":
		return Secrets{Tokens: []byte(oauthKey), Registrations: []byte(dataStoreKey)}, nil
	case oauthKey != "":
		return Secrets{Tokens: []byte(oauthKey), Registrations: []byte(oauthKey)}, nil
	case dataStoreKey != "":
		return Secrets{Tokens: []byte(dataStoreKey), Registrations: []byte(dataStoreKey)}, nil
	}
	log.Warnf("no datastore encryption key or %s set: MCP OAuth logins will not survive a restart or work across instances", EnvOAuthKey)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return Secrets{}, fmt.Errorf("generate MCP OAuth secret: %w", err)
	}
	return Secrets{Tokens: random, Registrations: random}, nil
}

// randomToken returns an unguessable URL-safe string.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// clientKey is a short fingerprint of a client id, carried in tokens instead of the id itself.
func clientKey(clientID string) string {
	sum := sha256.Sum256([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
