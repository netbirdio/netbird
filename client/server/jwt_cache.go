package server

import (
	"sync"
	"time"

	"github.com/awnumar/memguard"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

type jwtCache struct {
	mu      sync.RWMutex
	enclave *memguard.Enclave
	owner   *ipcauth.Identity

	expiresAt    time.Time
	timer        *time.Timer
	maxTokenSize int
}

func newJWTCache() *jwtCache {
	return &jwtCache{
		maxTokenSize: 8192,
	}
}

func (c *jwtCache) store(token string, owner ipcauth.Identity, maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanup()

	if c.timer != nil {
		c.timer.Stop()
	}

	tokenBytes := []byte(token)
	c.enclave = memguard.NewEnclave(tokenBytes)

	c.owner = &owner
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

// get returns the cached token to the identity that stored it.
func (c *jwtCache) get(caller ipcauth.Identity) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.enclave == nil || time.Now().After(c.expiresAt) {
		return "", false
	}

	if c.owner == nil || !c.owner.SameUser(caller) {
		log.Warnf("refusing the cached SSH JWT: caller %s is not the identity that obtained it", caller)
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

func (c *jwtCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.cleanup()
}

// cleanup destroys the secure enclave, must be called with lock held
func (c *jwtCache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.owner = nil
	c.expiresAt = time.Time{}
}
