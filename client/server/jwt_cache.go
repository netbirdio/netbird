package server

import (
	"sync"
	"time"

	"github.com/awnumar/memguard"
	gojwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

type jwtCache struct {
	mu           sync.RWMutex
	enclave      *memguard.Enclave
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

func (c *jwtCache) store(token string, maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.cleanup()

	if maxAge <= 0 {
		return
	}

	jwtToken, _, err := gojwt.NewParser().ParseUnverified(token, gojwt.MapClaims{})
	if err != nil {
		log.Debugf("Failed to parse JWT token claims for cache: %v", err)
		return
	}
	claims, ok := jwtToken.Claims.(gojwt.MapClaims)
	if !ok {
		log.Debug("JWT token has invalid claims format, not caching")
		return
	}

	now := time.Now()
	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Debugf("JWT token has invalid exp claim, not caching: %v", err)
		return
	}
	if exp != nil && !now.Before(exp.Time) {
		log.Debug("JWT token expired by exp claim, not caching")
		return
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		log.Debugf("JWT token has invalid iat claim, not caching: %v", err)
		return
	}
	if iat == nil {
		log.Debug("JWT token missing iat claim, not caching")
		return
	}
	tokenAge := now.Sub(iat.Time)
	if tokenAge < 0 {
		log.Debugf("JWT token has future iat claim, not caching: iat=%v, now=%v", iat.Time, now)
		return
	}

	if tokenAge > maxAge {
		log.Debugf("JWT token exceeded cache TTL by iat claim, not caching: age=%v, max=%v", tokenAge, maxAge)
		return
	}

	tokenBytes := []byte(token)
	c.enclave = memguard.NewEnclave(tokenBytes)
	c.issuedAt = iat.Time
	if exp != nil {
		c.expiresAt = exp.Time
	}

	cleanupAfter := maxAge - tokenAge
	if exp != nil {
		expiresIn := time.Until(exp.Time)
		if expiresIn < cleanupAfter {
			cleanupAfter = expiresIn
		}
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
}

func (c *jwtCache) get(maxAge time.Duration) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.enclave == nil {
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
		return "", found
	}
	defer buffer.Destroy()

	token := string(buffer.Bytes())
	if maxAge <= 0 {
		return "", found
	}

	now := time.Now()
	if !c.expiresAt.IsZero() && !now.Before(c.expiresAt) {
		log.Debug("Cached JWT token expired by exp claim")
		return "", found
	}

	if c.issuedAt.IsZero() {
		log.Debug("Cached JWT token missing iat claim")
		return "", found
	}

	tokenAge := now.Sub(c.issuedAt)
	if tokenAge < 0 {
		log.Debugf("JWT token has future iat claim, not caching: iat=%v, now=%v", c.issuedAt, now)
		return "", found
	}
	if tokenAge > maxAge {
		log.Debugf("Cached JWT token exceeded cache TTL by iat claim: age=%v, max=%v", now.Sub(c.issuedAt), maxAge)
		return "", found
	}

	found = true
	return token, found
}

// cleanup destroys the secure enclave, must be called with lock held
func (c *jwtCache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.issuedAt = time.Time{}
	c.expiresAt = time.Time{}
}
