package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/localmetrics"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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

// profileFixture points the profile globals at a temp dir holding a single
// default profile, which is the one ActiveProfileState.FilePath resolves
// without consulting the current OS user.
func profileFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	defaultConfig := filepath.Join(dir, "default.json")
	require.NoError(t, os.WriteFile(defaultConfig, []byte("{}"), 0o600))

	origDir := profilemanager.DefaultConfigPathDir
	origDefault := profilemanager.DefaultConfigPath
	origState := profilemanager.ActiveProfileStatePath
	origOverride := profilemanager.ConfigDirOverride

	profilemanager.DefaultConfigPathDir = dir
	profilemanager.DefaultConfigPath = defaultConfig
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.ConfigDirOverride = dir

	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.DefaultConfigPath = origDefault
		profilemanager.ActiveProfileStatePath = origState
		profilemanager.ConfigDirOverride = origOverride
	})

	return defaultConfig
}

// A profile carries its own NetBird account, so a token obtained under the
// previous one must not survive the switch even for the local user who
// obtained it.
func TestSwitchProfile_ClearsJWTCache(t *testing.T) {
	defaultConfig := profileFixture(t)

	s := newTestServer()
	s.profileManager = profilemanager.NewServiceManager(defaultConfig)
	s.localMetrics = localmetrics.NewManager(context.Background(), s.statusRecorder, nil)

	owner := unprivilegedIdentity()
	s.jwtCache.store("token", owner, testTTL)

	_, err := s.SwitchProfile(context.Background(), nil)
	require.NoError(t, err)

	_, found := s.jwtCache.get(owner)
	assert.False(t, found, "switching profile must drop the cached SSH JWT")
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
