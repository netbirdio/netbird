package server

import (
	"sync"
	"time"

	"github.com/awnumar/memguard"
	gojwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

type jwtCache struct {
	mu      sync.RWMutex
	enclave *memguard.Enclave
	owner   *ipcauth.Identity

	// generation counts the invalidations. A caller that starts an
	// authentication takes the generation first and hands it back to store, so
	// a token obtained under a session that ended while the IdP was being
	// polled cannot land in the cache the new session is using.
	generation uint64

	expiresAt    time.Time
	timer        *time.Timer
	maxTokenSize int
}

func newJWTCache() *jwtCache {
	return &jwtCache{
		maxTokenSize: 8192,
	}
}

func (c *jwtCache) currentGeneration() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.generation
}

// store keeps the token only while generation is still the current one, and
// reports whether it did. See the generation field.
func (c *jwtCache) store(token string, owner ipcauth.Identity, maxAge time.Duration, generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generation != generation {
		return false
	}

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

	return true
}

// get returns the cached token to the identity that stored it.
func (c *jwtCache) get(caller ipcauth.Identity, maxAge time.Duration) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.enclave == nil {
		return "", false
	}

	if c.owner == nil || !c.owner.SameUser(caller) {
		log.Warnf("refusing the cached SSH JWT: caller %s is not the identity that obtained it", caller)
		return "", false
	}
	
	found := false
	defer func() {
		if !found {
			c.cleanup()
		}
	}()

	buffer, err := c.enclave.Open()
	if err != nil {
		log.Debugf("Failed to open JWT token enclave: %v", err)
		return "", false
	}
	defer buffer.Destroy()

	token := string(buffer.Bytes())
	if maxAge <= 0 {
		return "", false
	}

	jwtToken, _, err := gojwt.NewParser().ParseUnverified(token, gojwt.MapClaims{})
	if err != nil {
		log.Debugf("Failed to parse cached JWT token claims: %v", err)
		return "", false
	}
	claims, ok := jwtToken.Claims.(gojwt.MapClaims)
	if !ok {
		log.Debug("Cached JWT token has invalid claims format")
		return "", false
	}

	now := time.Now()
	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Debugf("Cached JWT token has invalid exp claim: %v", err)
		return "", false
	}
	if exp != nil && !now.Before(exp.Time) {
		log.Debug("Cached JWT token expired by exp claim")
		return "", false
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		log.Debugf("Cached JWT token has invalid iat claim: %v", err)
		return "", false
	}
	if iat == nil {
		log.Debug("Cached JWT token missing iat claim")
		return "", false
	}
	if now.Sub(iat.Time) > maxAge {
		log.Debugf("Cached JWT token exceeded cache TTL by iat claim: age=%v, max=%v", now.Sub(iat.Time), maxAge)
		return "", false
	}

	found = true
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
	c.generation++
}

// cleanup destroys the secure enclave, must be called with lock held
func (c *jwtCache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.owner = nil
	c.expiresAt = time.Time{}
}
