package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

const testTTL = time.Minute

func unixCaller(uid uint32) ipcauth.Identity {
	return ipcauth.Identity{UID: uid, GID: uid}
}

func windowsCaller(sid string) ipcauth.Identity {
	return ipcauth.Identity{SID: sid}
}

func TestJWTCache_ServesTheOwner(t *testing.T) {
	c := newJWTCache()
	owner := unixCaller(1000)
	c.store("token-for-1000", owner, testTTL, c.currentGeneration())

	got, found := c.get(owner)

	require.True(t, found, "the identity that stored the token must get it back")
	assert.Equal(t, "token-for-1000", got)
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
			c.store("victim-token", tt.owner, testTTL, c.currentGeneration())

			got, found := c.get(tt.caller)

			assert.False(t, found, "a caller that is not the owner must get a miss")
			assert.Empty(t, got)
		})
	}
}

func TestJWTCache_EmptyCacheMatchesNobody(t *testing.T) {
	c := newJWTCache()

	got, found := c.get(unixCaller(0))

	assert.False(t, found)
	assert.Empty(t, got)
}

// An entry with no recorded owner must match nobody, root included: an
// unidentified caller arrives as the zero Identity, which carries uid 0. This
// pins the nil-owner guard rather than the comparison, so it sets up an entry
// that exists and then drops its owner.
func TestJWTCache_UnownedEntryMatchesNobody(t *testing.T) {
	c := newJWTCache()
	c.store("token", unixCaller(1000), testTTL, c.currentGeneration())
	c.owner = nil

	got, found := c.get(unixCaller(0))

	assert.False(t, found)
	assert.Empty(t, got)
}

// The same user calling once elevated and once not is still the same user, so
// hiding their own token from them would be wrong.
func TestJWTCache_ElevationDoesNotChangeTheOwner(t *testing.T) {
	c := newJWTCache()
	sid := "S-1-5-21-1-2-3-1001"
	owner := windowsCaller(sid)
	owner.Elevated = true
	c.store("token", owner, testTTL, c.currentGeneration())

	got, found := c.get(windowsCaller(sid))

	require.True(t, found)
	assert.Equal(t, "token", got)
}

func TestJWTCache_Expiry(t *testing.T) {
	c := newJWTCache()
	owner := unixCaller(1000)
	c.store("token", owner, testTTL, c.currentGeneration())
	c.expiresAt = time.Now().Add(-time.Second)

	_, found := c.get(owner)

	assert.False(t, found)
}

// Logout and SwitchProfile call clear — Down deliberately does not: the NetBird
// session the token speaks for is over, so not even its owner may have it back.
func TestJWTCache_ClearDropsTheEntry(t *testing.T) {
	c := newJWTCache()
	owner := unixCaller(1000)
	c.store("token", owner, testTTL, c.currentGeneration())

	c.clear()

	_, found := c.get(owner)
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
	owner := unixCaller(1000)

	// The generation a caller takes when its authentication starts.
	generation := c.currentGeneration()

	c.clear() // logout or profile switch, while the IdP is still being polled

	stored := c.store("stale-token", owner, testTTL, generation)

	assert.False(t, stored, "a token from an ended session must not be cached")
	_, found := c.get(owner)
	assert.False(t, found, "the cache must stay empty after the session ended")
}

// The same caller must still be able to store once it re-reads the generation, so
// the guard does not wedge the cache after any invalidation.
func TestJWTCache_StoreWorksAgainAfterClear(t *testing.T) {
	c := newJWTCache()
	owner := unixCaller(1000)

	c.clear()

	require.True(t, c.store("token", owner, testTTL, c.currentGeneration()))

	got, found := c.get(owner)
	require.True(t, found)
	assert.Equal(t, "token", got)
}

func TestJWTCache_StoreReplacesThePreviousOwner(t *testing.T) {
	c := newJWTCache()
	first := unixCaller(1000)
	second := unixCaller(1001)

	c.store("first-token", first, testTTL, c.currentGeneration())
	c.store("second-token", second, testTTL, c.currentGeneration())

	_, found := c.get(first)
	assert.False(t, found, "the previous owner must not reach the new token")

	got, found := c.get(second)
	require.True(t, found)
	assert.Equal(t, "second-token", got)
}
