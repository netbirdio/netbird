package hmac

import (
	"sync"
)

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
type TokenStore struct {
	mu    sync.Mutex
	token Token
}

func (a *TokenStore) UpdateToken(token Token) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

func (a *TokenStore) Token() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return marshalToken(a.token)
}
