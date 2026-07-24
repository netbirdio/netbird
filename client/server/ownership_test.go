package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util"
)

// writeTargetProfile writes a profile JSON with the given ownership and returns
// a Profile handle pointing at it (Path set, so FilePath() resolves directly).
func writeTargetProfile(t *testing.T, dir, id string, owners []string, shared bool) *profilemanager.Profile {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	cfg := &profilemanager.Config{Owners: owners, Shared: shared}
	require.NoError(t, util.WriteJson(context.Background(), path, cfg))
	return &profilemanager.Profile{ID: profilemanager.ID(id), Name: id, Path: path}
}

func readOwners(t *testing.T, path string) ([]string, bool) {
	t.Helper()
	cfg, err := profilemanager.GetConfig(path)
	require.NoError(t, err)
	return cfg.Owners, cfg.Shared
}

func TestAuthorizeTargetProfile(t *testing.T) {
	s := &Server{groupResolver: ipcauth.NewDefaultGroupResolver()}
	owner := ipcauth.Identity{UID: 1000}
	other := ipcauth.Identity{UID: 1001}
	root := ipcauth.Identity{UID: 0}

	t.Run("no identity denies", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", []string{"uid:1000"}, false)
		err := s.authorizeTargetProfile(context.Background(), p, true)
		assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
	})

	t.Run("privileged allowed on another's profile", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", []string{"uid:1000"}, false)
		assert.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(root), p, true))
	})

	t.Run("owner allowed", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", []string{"uid:1000"}, false)
		assert.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(owner), p, true))
	})

	t.Run("non-owner denied", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", []string{"uid:1000"}, false)
		err := s.authorizeTargetProfile(ctxWithIdentity(other), p, true)
		assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
	})

	t.Run("shared allows any caller", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", nil, true)
		assert.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(other), p, true))
	})

	t.Run("unowned claim stamps owner", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", nil, false)
		require.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(other), p, true))

		owners, shared := readOwners(t, p.Path)
		assert.Equal(t, []string{"uid:1001"}, owners)
		assert.False(t, shared)

		// A different caller is now locked out of the claimed profile.
		err := s.authorizeTargetProfile(ctxWithIdentity(owner), p, true)
		assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
	})

	t.Run("unowned without claim leaves profile unowned", func(t *testing.T) {
		p := writeTargetProfile(t, t.TempDir(), "p", nil, false)
		require.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(other), p, false))

		owners, _ := readOwners(t, p.Path)
		assert.Empty(t, owners)
	})
}
