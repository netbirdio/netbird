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

	issuedAt     time.Time
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

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.cleanup()

	if maxAge <= 0 {
		return false
	}

	jwtToken, _, err := gojwt.NewParser().ParseUnverified(token, gojwt.MapClaims{})
	if err != nil {
		log.Debugf("Failed to parse JWT token claims for cache: %v", err)
		return false
	}
	claims, ok := jwtToken.Claims.(gojwt.MapClaims)
	if !ok {
		log.Debug("JWT token has invalid claims format, not caching")
		return false
	}

	now := time.Now()
	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Debugf("JWT token has invalid exp claim, not caching: %v", err)
		return false
	}
	if exp != nil && !now.Before(exp.Time) {
		log.Debug("JWT token expired by exp claim, not caching")
		return false
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		log.Debugf("JWT token has invalid iat claim, not caching: %v", err)
		return false
	}
	if iat == nil {
		log.Debug("JWT token missing iat claim, not caching")
		return false
	}
	tokenAge := now.Sub(iat.Time)
	if tokenAge < 0 {
		log.Debugf("JWT token has future iat claim, not caching: iat=%v, now=%v", iat.Time, now)
		return false
	}

	if tokenAge > maxAge {
		log.Debugf("JWT token exceeded cache TTL by iat claim, not caching: age=%v, max=%v", tokenAge, maxAge)
		return false
	}

	tokenBytes := []byte(token)
	c.enclave = memguard.NewEnclave(tokenBytes)
	c.owner = &owner
	c.issuedAt = iat.Time
	cleanupAfter := maxAge - tokenAge
	if exp != nil {
		c.expiresAt = exp.Time
		cleanupAfter = min(cleanupAfter, time.Until(exp.Time))
	}

	var timer *time.Timer
	timer = time.AfterFunc(cleanupAfter, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.timer != timer {
			return
		}
		c.cleanup()
		c.timer = nil
		log.Debugf("JWT token cache expired after %v, securely wiped from memory", cleanupAfter)
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

	now := time.Now()
	tokenAge := now.Sub(c.issuedAt)
	if maxAge <= 0 || c.issuedAt.IsZero() || tokenAge < 0 || tokenAge > maxAge ||
		(!c.expiresAt.IsZero() && !now.Before(c.expiresAt)) {
		log.Debug("Cached JWT token is outside the current TTL or claim validity window")
		c.cleanup()
		return "", false
	}

	buffer, err := c.enclave.Open()
	if err != nil {
		log.Debugf("Failed to open JWT token enclave: %v", err)
		c.cleanup()
		return "", false
	}
	defer buffer.Destroy()

	return string(buffer.Bytes()), true
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
	c.issuedAt = time.Time{}
	c.expiresAt = time.Time{}
}
