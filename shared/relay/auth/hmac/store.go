package hmac

import (
	"encoding/base64"
	"fmt"
	"sync"

	v2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
)

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
type TokenStore struct {
	mu    sync.Mutex
	token []byte
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
	return nil
}

func (a *TokenStore) TokenBinary() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}
