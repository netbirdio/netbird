package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cover the RPC side of the cache: the cache itself is exercised in
// jwt_cache_test.go, but a correct cache buys nothing if the handlers around it
// consult the wrong identity or forget to clear it.

func TestCachedJWT_ServesTheOwner(t *testing.T) {
	s := newTestServer()
	owner := unprivilegedIdentity()
	s.jwtCache.store("token", owner, testTTL)

	got, found := s.cachedJWT(ctxWithIdentity(owner))

	require.True(t, found, "the identity that obtained the token must get it back")
	assert.Equal(t, "token", got)
}

func TestCachedJWT_RefusesAnotherCaller(t *testing.T) {
	s := newTestServer()
	s.jwtCache.store("token", unprivilegedIdentity(), testTTL)

	got, found := s.cachedJWT(ctxWithIdentity(privilegedIdentity()))

	assert.False(t, found, "a caller that did not obtain the token must get a miss")
	assert.Empty(t, got)
}

// A control channel that carries no caller identity — a TCP daemon socket, or a
// platform with no peer-credential primitive — cannot tell one local user from
// another, so cachedJWT must fail closed there.
func TestCachedJWT_WithoutCallerIdentity(t *testing.T) {
	s := newTestServer()
	s.jwtCache.store("token", unprivilegedIdentity(), testTTL)

	got, found := s.cachedJWT(context.Background())

	assert.False(t, found)
	assert.Empty(t, got)
}

// Logout and Down both go through cleanupConnection.
func TestCleanupConnection_ClearsJWTCache(t *testing.T) {
	s := newTestServer()
	_, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	owner := unprivilegedIdentity()
	s.jwtCache.store("token", owner, testTTL)

	require.NoError(t, s.cleanupConnection())

	_, found := s.jwtCache.get(owner)
	assert.False(t, found, "ending the session must drop the cached SSH JWT, owner included")
}
