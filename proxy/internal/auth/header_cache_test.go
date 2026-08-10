package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newCountingHeaderScheme(t *testing.T, kp *sessionkey.KeyPair, headerName, expectedValue string, calls *atomic.Int32) Header {
	t.Helper()
	token, err := sessionkey.SignToken(kp.PrivateKey, "header-user", "", "example.com", auth.MethodHeader, nil, nil, time.Hour)
	require.NoError(t, err)

	mock := &mockAuthenticator{fn: func(_ context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		calls.Add(1)
		ha := req.GetHeaderAuth()
		if ha != nil && ha.GetHeaderValue() == expectedValue {
			return &proto.AuthenticateResponse{Success: true, SessionToken: token}, nil
		}
		return &proto.AuthenticateResponse{Success: false}, nil
	}}
	return NewHeader(mock, "svc1", "acc1", headerName)
}

func doHeaderRequest(t *testing.T, mw *Middleware, credential string) *httptest.ResponseRecorder {
	t.Helper()
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set("X-API-Key", credential)
	req = req.WithContext(proxy.WithCapturedData(req.Context(), proxy.NewCapturedData("")))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestProtect_HeaderAuth_ReusesSessionTokenAcrossRequests(t *testing.T) {
	var calls atomic.Int32
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	hdr := newCountingHeaderScheme(t, kp, "X-API-Key", "secret-key", &calls)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	for i := 0; i < 25; i++ {
		rec := doHeaderRequest(t, mw, "secret-key")
		require.Equal(t, http.StatusOK, rec.Code)
	}

	assert.Equal(t, int32(1), calls.Load(), "a repeated credential must be verified once")
}

func TestProtect_HeaderAuth_DoesNotCacheFailures(t *testing.T) {
	var calls atomic.Int32
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	hdr := newCountingHeaderScheme(t, kp, "X-API-Key", "secret-key", &calls)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	for i := 0; i < 3; i++ {
		rec := doHeaderRequest(t, mw, "wrong-key")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	assert.Equal(t, int32(3), calls.Load(), "rejected credentials must not be cached")
}

func TestProtect_HeaderAuth_MissingHeaderSkipsRPC(t *testing.T) {
	var calls atomic.Int32
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	hdr := newCountingHeaderScheme(t, kp, "X-API-Key", "secret-key", &calls)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	rec := doHeaderRequest(t, mw, "")
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Zero(t, calls.Load(), "an absent header must not reach management")
}

func TestHeaderAuthCache_EvictsExpiredEntries(t *testing.T) {
	c := newHeaderAuthCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	key := c.key("svc1", "X-API-Key", "secret")
	c.put(key, "token", time.Hour)
	require.Equal(t, "token", c.get(key))

	now = now.Add(c.ttl + time.Second)
	assert.Empty(t, c.get(key))
}

func TestHeaderAuthCache_SkipsCacheWhenSessionExpiresWithinSkew(t *testing.T) {
	c := newHeaderAuthCache()

	key := c.key("svc1", "X-API-Key", "secret")
	c.put(key, "token", headerAuthCacheSkew)

	assert.Empty(t, c.get(key), "a token must never outlive the session it was minted for")
}

func TestHeaderAuthCache_SessionExpirationShortensTTL(t *testing.T) {
	c := newHeaderAuthCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	key := c.key("svc1", "X-API-Key", "secret")
	c.put(key, "token", headerAuthCacheSkew+10*time.Second)
	require.Equal(t, "token", c.get(key))

	now = now.Add(11 * time.Second)
	assert.Empty(t, c.get(key))
}

func TestHeaderAuthCache_BoundsEntriesPerService(t *testing.T) {
	c := newHeaderAuthCache()
	c.maxSize = 4

	var first headerCacheKey
	for i := 0; i < 10; i++ {
		key := c.key("svc1", "X-API-Key", fmt.Sprintf("secret-%d", i))
		if i == 0 {
			first = key
		}
		c.put(key, "token", time.Hour)
	}

	assert.Len(t, c.entries["svc1"].items, 4)
	assert.Empty(t, c.get(first), "the oldest entry must be evicted")
}

func TestHeaderAuthCache_DistinguishesCredentials(t *testing.T) {
	c := newHeaderAuthCache()

	good := c.key("svc1", "X-API-Key", "good")
	other := c.key("svc1", "X-API-Key", "other")
	c.put(good, "token", time.Hour)

	assert.Equal(t, "token", c.get(good))
	assert.Empty(t, c.get(other))
}

func TestProtect_HeaderAuth_MappingUpdateInvalidatesCache(t *testing.T) {
	var calls atomic.Int32
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	hdr := newCountingHeaderScheme(t, kp, "X-API-Key", "secret-key", &calls)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	require.Equal(t, http.StatusOK, doHeaderRequest(t, mw, "secret-key").Code)
	require.Equal(t, int32(1), calls.Load())

	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	require.Equal(t, http.StatusOK, doHeaderRequest(t, mw, "secret-key").Code)
	assert.Equal(t, int32(2), calls.Load(), "a mapping update must drop the service's cached credentials")
}

func TestHeaderAuthCache_InvalidateService(t *testing.T) {
	c := newHeaderAuthCache()

	key := c.key("svc1", "X-API-Key", "secret")
	other := c.key("svc2", "X-API-Key", "secret")
	c.put(key, "token", time.Hour)
	c.put(other, "token", time.Hour)

	c.invalidateService("svc1")

	assert.Empty(t, c.get(key))
	assert.Equal(t, "token", c.get(other), "other services must be untouched")
}

func TestHeaderAuthCache_Invalidate(t *testing.T) {
	c := newHeaderAuthCache()

	key := c.key("svc1", "X-API-Key", "secret")
	other := c.key("svc1", "X-API-Key", "second")
	c.put(key, "token", time.Hour)
	c.put(other, "token", time.Hour)

	c.invalidate(key)

	assert.Empty(t, c.get(key))
	assert.Equal(t, "token", c.get(other))
}

func TestProtect_HeaderAuth_RevalidatesWhenCachedTokenRejected(t *testing.T) {
	var calls atomic.Int32
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	hdr := newCountingHeaderScheme(t, kp, "X-API-Key", "secret-key", &calls)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false))

	key := mw.headerCache.key("svc1", "X-API-Key", "secret-key")
	mw.headerCache.put(key, "not-a-valid-token", time.Hour)

	rec := doHeaderRequest(t, mw, "secret-key")

	assert.Equal(t, http.StatusOK, rec.Code, "an unusable cached token must not fail the request")
	assert.Equal(t, int32(1), calls.Load(), "the credential must be re-verified once")
}

func TestHeaderAuthCache_CollapsesConcurrentMisses(t *testing.T) {
	c := newHeaderAuthCache()
	key := c.key("svc1", "X-API-Key", "secret")

	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = c.fetch(key, time.Hour, func() (string, error) {
				calls.Add(1)
				<-release
				return "token", nil
			})
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load(), "a burst of cold requests must collapse into one RPC")
}
