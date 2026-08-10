package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

const headerAuthCacheTTL = 60 * time.Second

const envHeaderAuthCacheTTL = "NB_PROXY_HEADER_AUTH_CACHE_TTL"

const headerAuthCachePerService = 1024

const headerAuthCacheSkew = 30 * time.Second

const headerAuthRPCTimeout = 10 * time.Second

type headerCacheKey struct {
	serviceID  types.ServiceID
	headerName string
	credential [sha256.Size]byte
}

type headerCacheEntry struct {
	token     string
	expiresAt time.Time
}

type headerAuthCache struct {
	mu      sync.Mutex
	entries map[types.ServiceID]*headerServiceBucket
	flight  singleflight.Group
	ttl     time.Duration
	maxSize int
	macKey  []byte
	now     func() time.Time
}

type headerServiceBucket struct {
	items map[headerCacheKey]headerCacheEntry
	order []headerCacheKey
}

func newHeaderAuthCache() *headerAuthCache {
	macKey := make([]byte, sha256.Size)
	_, _ = rand.Read(macKey)

	return &headerAuthCache{
		entries: make(map[types.ServiceID]*headerServiceBucket),
		ttl:     headerAuthCacheTTLFromEnv(),
		maxSize: headerAuthCachePerService,
		macKey:  macKey,
		now:     time.Now,
	}
}

func headerAuthCacheTTLFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envHeaderAuthCacheTTL))
	if raw == "" {
		return headerAuthCacheTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Warnf("ignoring invalid %s=%q (want a positive Go duration like 30s or 2m); using default %s",
			envHeaderAuthCacheTTL, raw, headerAuthCacheTTL)
		return headerAuthCacheTTL
	}
	return d
}

func (c *headerAuthCache) key(serviceID types.ServiceID, headerName, credential string) headerCacheKey {
	mac := hmac.New(sha256.New, c.macKey)
	mac.Write([]byte(credential))

	key := headerCacheKey{serviceID: serviceID, headerName: headerName}
	copy(key.credential[:], mac.Sum(nil))
	return key
}

func (c *headerAuthCache) get(key headerCacheKey) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.entries[key.serviceID]
	if !ok {
		return ""
	}
	entry, ok := bucket.items[key]
	if !ok {
		return ""
	}
	if !c.now().Before(entry.expiresAt) {
		delete(bucket.items, key)
		bucket.order = removeKey(bucket.order, key)
		return ""
	}
	return entry.token
}

func (c *headerAuthCache) put(key headerCacheKey, token string, sessionExpiration time.Duration) {
	lifetime := c.ttl
	if sessionExpiration > 0 && sessionExpiration-headerAuthCacheSkew < lifetime {
		lifetime = sessionExpiration - headerAuthCacheSkew
	}
	if lifetime <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.entries[key.serviceID]
	if !ok {
		bucket = &headerServiceBucket{items: make(map[headerCacheKey]headerCacheEntry)}
		c.entries[key.serviceID] = bucket
	}
	if _, exists := bucket.items[key]; !exists {
		bucket.order = append(bucket.order, key)
	}
	bucket.items[key] = headerCacheEntry{token: token, expiresAt: c.now().Add(lifetime)}

	for len(bucket.order) > c.maxSize {
		oldest := bucket.order[0]
		bucket.order = bucket.order[1:]
		delete(bucket.items, oldest)
	}
}

func (c *headerAuthCache) invalidate(key headerCacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.entries[key.serviceID]
	if !ok {
		return
	}
	delete(bucket.items, key)
	bucket.order = removeKey(bucket.order, key)
}

func (c *headerAuthCache) invalidateService(serviceID types.ServiceID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, serviceID)
}

type authenticateHeaderFn func() (string, error)

func (c *headerAuthCache) fetch(key headerCacheKey, sessionExpiration time.Duration, authenticate authenticateHeaderFn) (string, bool, error) {
	if token := c.get(key); token != "" {
		return token, true, nil
	}

	res, err, _ := c.flight.Do(headerFlightKey(key), func() (any, error) {
		if token := c.get(key); token != "" {
			return token, nil
		}
		token, err := authenticate()
		if err != nil {
			return "", err
		}
		if token != "" {
			c.put(key, token, sessionExpiration)
		}
		return token, nil
	})
	if err != nil {
		return "", false, err
	}

	token, _ := res.(string)
	return token, false, nil
}

func headerFlightKey(key headerCacheKey) string {
	return string(key.serviceID) + "|" + key.headerName + "|" + string(key.credential[:])
}
