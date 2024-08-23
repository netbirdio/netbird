package hmac

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// TokenStore is a simple in-memory store for token
// With this can update the token in thread safe way
type TokenStore struct {
	mu    sync.Mutex
	token []byte
}

func (a *TokenStore) UpdateToken(token *Token) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if token == nil {
		return
	}

	t, err := marshalToken(*token)
	if err != nil {
		log.Errorf("failed to marshal token: %s", err)
	}
	a.token = t
}

func (a *TokenStore) TokenBinary() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.token
}
