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

// cleanup destroys the secure enclave, must be called with lock held
func (c *jwtCache) cleanup() {
	if c.enclave != nil {
		c.enclave = nil
	}
	c.expiresAt = time.Time{}
}
