package auth

import (
	"context"
	"testing"
	"time"

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

func TestHashToken_StableAndDoesNotLeak(t *testing.T) {
	a := hashToken("tokenA")
	b := hashToken("tokenB")
	assert.Equal(t, a, hashToken("tokenA"), "hash must be deterministic")
	assert.NotEqual(t, a, b, "different tokens must hash differently")
	assert.Len(t, a, 64, "sha256 hex must be 64 chars")
	assert.NotContains(t, a, "tokenA", "raw token must not appear in hash")
}
