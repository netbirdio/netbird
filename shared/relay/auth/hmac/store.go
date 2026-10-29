package hmac

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	v2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
type TokenStore struct {
	mu    sync.Mutex
	token []byte
	// authToken marks token as the auth token, which is presented with a proof of the auth key.
	authToken bool
}

func (a *TokenStore) UpdateToken(token *Token) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if token == nil {
		return nil
	}

	sig, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	tok := v2.Token{
		AuthAlgo:  v2.AuthAlgoHMACSHA256,
		Signature: sig,
		Payload:   []byte(token.Payload),
	}

	a.token = tok.Marshal()
	a.authToken = false
	return nil
}

// UpdateAuthToken replaces the current token with the auth token, kept as received.
func (a *TokenStore) UpdateAuthToken(token []byte) error {
	if len(token) == 0 {
		return errors.New("empty auth token")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = append([]byte(nil), token...)
	a.authToken = true
	return nil
}

// Credentials returns the current token and whether it is the auth token.
func (a *TokenStore) Credentials() ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token, a.authToken
}

func (a *TokenStore) TokenBinary() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}
