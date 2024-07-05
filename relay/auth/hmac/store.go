package hmac

import (
	"sync"
)

// Store is a simple in-memory store for token
// With this can update the token in thread safe way
type Store struct {
	mu    sync.Mutex
	token Token
}

func (a *Store) UpdateToken(token Token) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = token
}

func (a *Store) Token() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return marshalToken(a.token)
}
