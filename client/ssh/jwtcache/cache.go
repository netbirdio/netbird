// Package jwtcache provides an in-memory, TTL-bound cache for SSH JWT tokens.
// The token is kept in a secure memguard enclave and wiped from memory when it
// expires. It is shared by the daemon gRPC server and the mobile SDKs, which
// have no daemon process to delegate caching to.
package jwtcache

import (
	"sync"
	"time"

	"github.com/awnumar/memguard"
	log "github.com/sirupsen/logrus"
)

// DefaultTTL is used when no TTL is configured: caching disabled.
const DefaultTTL = 0

// Cache stores a single JWT token in a secure enclave until it expires.
type Cache struct {
	mu           sync.RWMutex
	enclave      *memguard.Enclave
	expiresAt    time.Time
	timer        *time.Timer
	maxTokenSize int
}

// New creates an empty Cache.
func New() *Cache {
	return &Cache{
		maxTokenSize: 8192,
	}
}

// Store caches the token for maxAge. A previously stored token is wiped.
func (c *Cache) Store(token string, maxAge time.Duration) {
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

// Get returns the cached token, or false if none is stored or it has expired.
func (c *Cache) Get() (string, bool) {
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
func (c *Cache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.expiresAt = time.Time{}
}

// ResolveTTL converts the configured TTL (seconds, from
// profilemanager.Config.SSHJWTCacheTTL) into a duration. Returns DefaultTTL
// when unset; 0 means caching is disabled.
func ResolveTTL(configuredSeconds *int) time.Duration {
	if configuredSeconds == nil {
		return DefaultTTL
	}

	seconds := *configuredSeconds
	if seconds == 0 {
		log.Debug("SSH JWT cache disabled (configured to 0)")
		return 0
	}

	ttl := time.Duration(seconds) * time.Second
	log.Debugf("SSH JWT cache TTL set to %v from config", ttl)
	return ttl
}
