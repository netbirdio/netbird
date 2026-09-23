package server

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

const testTTL = time.Minute

func newJWTCacheToken(t *testing.T, subject string) string {
	t.Helper()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": subject,
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)
	return signed
}

func unixCaller(uid uint32) ipcauth.Identity {
	return ipcauth.Identity{UID: uid, GID: uid}
}

func windowsCaller(sid string) ipcauth.Identity {
	return ipcauth.Identity{SID: sid}
}

func TestJWTCache_ServesTheOwner(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	owner := unixCaller(1000)
	token := newJWTCacheToken(t, "token-for-1000")
	require.True(t, c.store(token, owner, testTTL, c.currentGeneration()), "valid fixture must be cached")

	got, found := c.get(owner, testTTL)

	require.True(t, found, "the identity that stored the token must get it back")
	assert.Equal(t, token, got, "cached token must match the stored token")
}

// The disclosure this cache guards against: one local account collecting the
// SSH JWT another account's authentication put in the daemon-wide cache.
func TestJWTCache_RefusesAnotherLocalUser(t *testing.T) {
	tests := []struct {
		name   string
		owner  ipcauth.Identity
		caller ipcauth.Identity
	}{
		{"different uid", unixCaller(1000), unixCaller(65534)},
		{"root is not the owner either", unixCaller(1000), unixCaller(0)},
		{"different sid", windowsCaller("S-1-5-21-1-2-3-1001"), windowsCaller("S-1-5-21-1-2-3-1002")},
		{"windows caller against a unix owner", unixCaller(0), windowsCaller("S-1-5-18")},
		{"unix caller against a windows owner", windowsCaller("S-1-5-18"), unixCaller(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newJWTCache()
			t.Cleanup(c.clear)
			token := newJWTCacheToken(t, "victim-token")
			require.True(t, c.store(token, tt.owner, testTTL, c.currentGeneration()), "valid fixture must be cached")

			got, found := c.get(tt.caller, testTTL)

			assert.False(t, found, "a caller that is not the owner must get a miss")
			assert.Empty(t, got)
			got, found = c.get(tt.owner, testTTL)
			require.True(t, found, "refusing another caller must preserve the owner's token")
			assert.Equal(t, token, got, "the owner must still receive the stored token")
		})
	}
}

func TestJWTCache_EmptyCacheMatchesNobody(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)

	got, found := c.get(unixCaller(0), testTTL)

	assert.False(t, found)
	assert.Empty(t, got)
}

// An entry with no recorded owner must match nobody, root included: an
// unidentified caller arrives as the zero Identity, which carries uid 0. This
// pins the nil-owner guard rather than the comparison, so it sets up an entry
// that exists and then drops its owner.
func TestJWTCache_UnownedEntryMatchesNobody(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	token := newJWTCacheToken(t, "token")
	require.True(t, c.store(token, unixCaller(1000), testTTL, c.currentGeneration()), "valid fixture must be cached")
	c.mu.Lock()
	c.owner = nil
	c.mu.Unlock()

	got, found := c.get(unixCaller(0), testTTL)

	assert.False(t, found)
	assert.Empty(t, got)
}

// The same user calling once elevated and once not is still the same user, so
// hiding their own token from them would be wrong.
func TestJWTCache_ElevationDoesNotChangeTheOwner(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	sid := "S-1-5-21-1-2-3-1001"
	owner := windowsCaller(sid)
	owner.Elevated = true
	token := newJWTCacheToken(t, "token")
	require.True(t, c.store(token, owner, testTTL, c.currentGeneration()), "valid fixture must be cached")

	got, found := c.get(windowsCaller(sid), testTTL)

	require.True(t, found)
	assert.Equal(t, token, got, "cached token must match the stored token")
}

func TestJWTCache_Expiry(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	owner := unixCaller(1000)
	token := newJWTCacheToken(t, "token")
	require.True(t, c.store(token, owner, testTTL, c.currentGeneration()), "valid fixture must be cached")
	c.mu.Lock()
	c.expiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	_, found := c.get(owner, testTTL)

	assert.False(t, found)
}

// Logout and SwitchProfile call clear — Down deliberately does not: the NetBird
// session the token speaks for is over, so not even its owner may have it back.
func TestJWTCache_ClearDropsTheEntry(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	owner := unixCaller(1000)
	token := newJWTCacheToken(t, "token")
	require.True(t, c.store(token, owner, testTTL, c.currentGeneration()), "valid fixture must be cached")

	c.clear()

	_, found := c.get(owner, testTTL)
	assert.False(t, found)
	assert.Nil(t, c.owner, "clear must forget the owner too")
	assert.Nil(t, c.timer, "clear must stop the expiry timer")
}

// WaitJWTToken polls the IdP unlocked, so a logout or a profile switch can
// clear the cache while a flow is still in the air. The token that flow returns
// belongs to the session that ended, so it must not land in the cache the new
// session is using.
func TestJWTCache_StoreFromAnEndedSessionIsDropped(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	owner := unixCaller(1000)

	// The generation a caller takes when its authentication starts.
	generation := c.currentGeneration()

	c.clear() // logout or profile switch, while the IdP is still being polled

	token := newJWTCacheToken(t, "stale-token")
	stored := c.store(token, owner, testTTL, generation)

	assert.False(t, stored, "a token from an ended session must not be cached")
	_, found := c.get(owner, testTTL)
	assert.False(t, found, "the cache must stay empty after the session ended")
}

// The same caller must still be able to store once it re-reads the generation, so
// the guard does not wedge the cache after any invalidation.
func TestJWTCache_StoreWorksAgainAfterClear(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	owner := unixCaller(1000)

	c.clear()

	token := newJWTCacheToken(t, "token")
	require.True(t, c.store(token, owner, testTTL, c.currentGeneration()), "valid fixture must be cached")

	got, found := c.get(owner, testTTL)
	require.True(t, found)
	assert.Equal(t, token, got, "cached token must match the stored token")
}

func TestJWTCache_StoreReplacesThePreviousOwner(t *testing.T) {
	c := newJWTCache()
	t.Cleanup(c.clear)
	first := unixCaller(1000)
	second := unixCaller(1001)

	firstToken := newJWTCacheToken(t, "first-token")
	require.True(t, c.store(firstToken, first, testTTL, c.currentGeneration()), "valid fixture must be cached")
	secondToken := newJWTCacheToken(t, "second-token")
	require.True(t, c.store(secondToken, second, testTTL, c.currentGeneration()), "valid fixture must be cached")

	_, found := c.get(first, testTTL)
	assert.False(t, found, "the previous owner must not reach the new token")

	got, found := c.get(second, testTTL)
	require.True(t, found)
	assert.Equal(t, secondToken, got, "cached token must match the stored token")
}

func TestJWTCacheValidatesTokenClaims(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		name  string
		ttl   time.Duration
		claim gojwt.MapClaims
		valid bool
	}{
		{
			name:  "disabled cache",
			claim: gojwt.MapClaims{"iat": now.Add(-time.Second).Unix()},
		},
		{
			name:  "negative ttl",
			ttl:   -time.Minute,
			claim: gojwt.MapClaims{"iat": now.Add(-time.Second).Unix()},
		},
		{
			name:  "future iat",
			ttl:   time.Hour,
			claim: gojwt.MapClaims{"iat": now.Add(time.Minute).Unix()},
		},
		{
			name:  "invalid iat",
			ttl:   time.Hour,
			claim: gojwt.MapClaims{"iat": "invalid"},
		},
		{
			name:  "missing exp uses max age",
			ttl:   time.Hour,
			claim: gojwt.MapClaims{"iat": now.Add(-time.Second).Unix()},
			valid: true,
		},
		{
			name: "valid token within iat ttl",
			ttl:  time.Minute,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": now.Add(time.Hour).Unix(),
			},
			valid: true,
		},
		{
			name: "expired exp claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": now.Add(-time.Second).Unix(),
			},
		},
		{
			name: "iat exceeds current ttl",
			ttl:  time.Minute,
			claim: gojwt.MapClaims{
				"iat": now.Add(-2 * time.Minute).Unix(),
				"exp": now.Add(time.Hour).Unix(),
			},
		},
		{
			name: "missing iat claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"exp": now.Add(time.Hour).Unix(),
			},
		},
		{
			name: "invalid exp claim",
			ttl:  time.Hour,
			claim: gojwt.MapClaims{
				"iat": now.Add(-30 * time.Second).Unix(),
				"exp": "invalid",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, tc.claim)
			tokenString, err := token.SignedString([]byte("secret"))
			require.NoError(t, err)

			cache := newJWTCache()
			t.Cleanup(cache.clear)
			stored := cache.store(tokenString, unixCaller(1000), tc.ttl, cache.currentGeneration())
			assert.Equal(t, tc.valid, stored, "store must respect token claims and TTL")

			cachedToken, found := cache.get(unixCaller(1000), tc.ttl)
			require.Equal(t, tc.valid, found, "only valid tokens may be returned")
			if tc.valid {
				assert.Equal(t, tokenString, cachedToken, "cached token must match the stored token")
			} else {
				assert.Empty(t, cachedToken, "rejected tokens must not be returned")
			}
		})
	}
}

func TestJWTCacheRejectsMalformedToken(t *testing.T) {
	cache := newJWTCache()
	t.Cleanup(cache.clear)
	owner := unixCaller(1000)

	assert.False(t, cache.store("not-a-jwt", owner, testTTL, cache.currentGeneration()),
		"malformed tokens must not be cached")
	token, found := cache.get(owner, testTTL)
	assert.False(t, found, "a rejected token must leave the cache empty")
	assert.Empty(t, token, "a malformed token must not be returned")
}

func TestJWTCacheGetUsesCurrentTTL(t *testing.T) {
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"iat": now.Add(-2 * time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	cache := newJWTCache()
	t.Cleanup(cache.clear)
	require.True(t, cache.store(tokenString, unixCaller(1000), time.Hour, cache.currentGeneration()), "valid fixture must be cached")

	cachedToken, found := cache.get(unixCaller(1000), time.Minute)
	require.False(t, found)
	require.Empty(t, cachedToken)
}
