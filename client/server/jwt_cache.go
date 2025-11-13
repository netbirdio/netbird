package server

import (
	"sync"
	"time"

	"github.com/awnumar/memguard"
	log "github.com/sirupsen/logrus"
)

type jwtCache struct {
	mu           sync.RWMutex
	enclave      *memguard.Enclave
	expiresAt    time.Time
	timer        *time.Timer
	maxTokenSize int
}

func newJWTCache() *jwtCache {
	return &jwtCache{
		maxTokenSize: 8192,
	}
}

func (c *jwtCache) store(token string, maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanup()

	if c.timer != nil {
		c.timer.Stop()
	}

	tokenBytes := []byte(token)
	c.enclave = memguard.NewEnclave(tokenBytes)

	c.expiresAt = time.Now().Add(maxAge)

	var timer *time.Timer
	timer = time.AfterFunc(maxAge, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.timer != timer {
			return
		}
		c.cleanup()
		c.timer = nil
		log.Debugf("JWT token cache expired after %v, securely wiped from memory", maxAge)
	})
	c.timer = timer
}

func (c *jwtCache) get() (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.enclave == nil || time.Now().After(c.expiresAt) {
		return "", false
	}

	buffer, err := c.enclave.Open()
	if err != nil {
		log.Debugf("Failed to open JWT token enclave: %v", err)
		return "", false
	}
	defer buffer.Destroy()

	token := string(buffer.Bytes())
	return token, true
}

// cleanup destroys the secure enclave, must be called with lock held
func (c *jwtCache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.expiresAt = time.Time{}
}
