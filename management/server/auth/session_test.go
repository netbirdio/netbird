package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcache "github.com/netbirdio/netbird/management/server/cache"
)

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	cacheStore, err := nbcache.NewStore(context.Background(), time.Hour, time.Hour, 100)
	require.NoError(t, err)
	return NewSessionStore(cacheStore)
}

func TestSessionStore_FirstRegisterSucceeds(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()

	require.NoError(t, s.RegisterToken(ctx, "token", time.Now().Add(time.Hour)))
}

func TestSessionStore_RegisterSameTokenTwiceIsRejected(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()
	token := "token"
	exp := time.Now().Add(time.Hour)

	require.NoError(t, s.RegisterToken(ctx, token, exp))

	err := s.RegisterToken(ctx, token, exp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenAlreadyUsed)
}

func TestSessionStore_ConcurrentRegistrationAllowsOneCaller(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()
	const attempts = 100

	start := make(chan struct{})
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			<-start
			results <- s.RegisterToken(ctx, "token", time.Now().Add(time.Hour))
		}()
	}
	close(start)

	succeeded := 0
	alreadyUsed := 0
	for range attempts {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTokenAlreadyUsed):
			alreadyUsed++
		default:
			require.NoError(t, err, "concurrent registration returned an unexpected error")
		}
	}

	assert.Equal(t, 1, succeeded, "exactly one concurrent caller should register the token")
	assert.Equal(t, attempts-1, alreadyUsed, "every other caller should be rejected as already used")
}

func TestSessionStore_RegisterDifferentTokensAreIndependent(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	require.NoError(t, s.RegisterToken(ctx, "tokenA", exp))
	require.NoError(t, s.RegisterToken(ctx, "tokenB", exp))
}

func TestSessionStore_RegisterWithPastExpiryIsRejected(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()
	token := "token"

	err := s.RegisterToken(ctx, token, time.Now().Add(-time.Second))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestSessionStore_EntryEvictsAtTTLAndAllowsReRegistration(t *testing.T) {
	s := newTestSessionStore(t)
	ctx := context.Background()
	token := "token"

	require.NoError(t, s.RegisterToken(ctx, token, time.Now().Add(50*time.Millisecond)))

	err := s.RegisterToken(ctx, token, time.Now().Add(50*time.Millisecond))
	assert.ErrorIs(t, err, ErrTokenAlreadyUsed)

	time.Sleep(120 * time.Millisecond)

	require.NoError(t, s.RegisterToken(ctx, token, time.Now().Add(time.Hour)))
}

type failingTokenCache struct {
	err error
}

func (f failingTokenCache) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return false, f.err
}

func TestSessionStore_CacheErrorIsReturned(t *testing.T) {
	cacheErr := errors.New("cache unavailable")
	s := NewSessionStore(failingTokenCache{err: cacheErr})

	err := s.RegisterToken(context.Background(), "token", time.Now().Add(time.Hour))
	require.Error(t, err, "cache failure should be surfaced to the caller")
	assert.ErrorIs(t, err, cacheErr, "cache error should be wrapped, not replaced")
}

func TestHashToken_StableAndDoesNotLeak(t *testing.T) {
	a := hashToken("tokenA")
	b := hashToken("tokenB")
	assert.Equal(t, a, hashToken("tokenA"), "hash must be deterministic")
	assert.NotEqual(t, a, b, "different tokens must hash differently")
	assert.Len(t, a, 64, "sha256 hex must be 64 chars")
	assert.NotContains(t, a, "tokenA", "raw token must not appear in hash")
}

func TestSessionStore_NoncanonicalSpellingIsRejectedAsReplay(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	canonical, err := token.SignedString(privateKey)
	require.NoError(t, err)

	parts := strings.Split(canonical, ".")
	require.Len(t, parts, 3)

	// A 256-byte RSA signature (256 mod 3 == 1) leaves unused bits in the final
	// base64url character; flip one without changing the decoded signature.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, parts[2][len(parts[2])-1])
	require.GreaterOrEqual(t, last, 0)
	require.Equal(t, 0, last&3, "unexpected canonical RSA signature encoding")

	equivalentSig := parts[2][:len(parts[2])-1] + string(alphabet[last|1])
	equivalent := parts[0] + "." + parts[1] + "." + equivalentSig
	require.NotEqual(t, canonical, equivalent, "spellings must differ as strings")

	// Same decoded signature bytes, so they verify as the same JWT.
	canonicalSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	altSig, err := base64.RawURLEncoding.DecodeString(equivalentSig)
	require.NoError(t, err)
	require.Equal(t, canonicalSig, altSig, "spellings must decode to identical signature bytes")

	// The replay-cache key must be identical for both spellings.
	assert.Equal(t, hashToken(canonical), hashToken(equivalent),
		"noncanonical spelling must map to the same replay-cache key")

	s := newTestSessionStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	require.NoError(t, s.RegisterToken(ctx, canonical, exp), "first claim should succeed")
	err = s.RegisterToken(ctx, equivalent, exp)
	require.Error(t, err, "alternate spelling must be treated as a replay")
	assert.ErrorIs(t, err, ErrTokenAlreadyUsed)
}
