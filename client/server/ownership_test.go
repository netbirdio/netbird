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
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

// fakeOwnerStore is an in-memory server.DaemonOwnerStore for tests.
type fakeOwnerStore struct {
	owners []string
	shared bool
}

func (f *fakeOwnerStore) Load() ([]string, bool, error) { return f.owners, f.shared, nil }
func (f *fakeOwnerStore) Save(o []string, s bool) error  { f.owners, f.shared = o, s; return nil }

// useTempProfileDirs points the profilemanager globals at a temp dir so
// GetActiveProfileState resolves to the default profile without touching /etc.
func useTempProfileDirs(t *testing.T) {
	t.Helper()
	tempDir := t.TempDir()
	origDir := profilemanager.DefaultConfigPathDir
	origActive := profilemanager.ActiveProfileStatePath
	origDefault := profilemanager.DefaultConfigPath
	profilemanager.ConfigDirOverride = tempDir
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = filepath.Join(tempDir, "active_profile.json")
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.ActiveProfileStatePath = origActive
		profilemanager.DefaultConfigPath = origDefault
		profilemanager.ConfigDirOverride = ""
	})
}

// TestDaemonOwnerPolicyDefaultProfile exercises the daemon-wide owner branch that
// governs the default profile: TOFU claim, add and reset, all via the store.
func TestDaemonOwnerPolicyDefaultProfile(t *testing.T) {
	useTempProfileDirs(t)

	store := &fakeOwnerStore{}
	s := &Server{profileManager: &profilemanager.ServiceManager{}, groupResolver: ipcauth.NewDefaultGroupResolver()}
	s.SetDaemonOwnerStore(store)

	// Active profile is the default, daemon is unowned to start.
	o := s.ActiveProfileOwnership()
	assert.Empty(t, o.Owners)
	assert.False(t, o.Shared)

	// Trust-on-first-use: the first caller claims daemon ownership, persisted.
	claimed, err := s.ClaimActiveProfileOwnerIfUnowned(ipcauth.Identity{UID: 1000})
	require.NoError(t, err)
	assert.True(t, claimed)
	assert.Equal(t, []string{"uid:1000"}, store.owners)
	assert.Equal(t, []string{"uid:1000"}, s.ActiveProfileOwnership().Owners)

	// A second, different caller does not re-claim an owned daemon.
	claimed, err = s.ClaimActiveProfileOwnerIfUnowned(ipcauth.Identity{UID: 1001})
	require.NoError(t, err)
	assert.False(t, claimed)

	// AddOwner appends a daemon-wide principal (persisted). The caller must be a
	// daemon owner: uid:1000 claimed ownership above.
	_, err = s.AddOwner(ctxWithIdentity(ipcauth.Identity{UID: 1000}), &proto.AddOwnerRequest{Principal: "uid:1001"})
	require.NoError(t, err)
	assert.Equal(t, []string{"uid:1000", "uid:1001"}, store.owners)

	// ResetOwner (privileged) clears the daemon owner set.
	_, err = s.ResetOwner(ctxWithIdentity(ipcauth.Identity{UID: 0}), &proto.ResetOwnerRequest{})
	require.NoError(t, err)
	assert.Empty(t, store.owners)
	assert.False(t, store.shared)
}

// TestOwnerMutationsRequireDaemonOwner checks the handler defense-in-depth: a
// caller who is neither a daemon owner nor privileged is denied at the handler.
func TestOwnerMutationsRequireDaemonOwner(t *testing.T) {
	store := &fakeOwnerStore{owners: []string{"uid:1000"}}
	s := &Server{groupResolver: ipcauth.NewDefaultGroupResolver()}
	s.SetDaemonOwnerStore(store) // loads {uid:1000} into s.owners

	owner := ctxWithIdentity(ipcauth.Identity{UID: 1000})
	nonOwner := ctxWithIdentity(ipcauth.Identity{UID: 2000})
	root := ctxWithIdentity(ipcauth.Identity{UID: 0})

	t.Run("AddOwner denied for non-daemon-owner", func(t *testing.T) {
		_, err := s.AddOwner(nonOwner, &proto.AddOwnerRequest{Principal: "uid:2000"})
		assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
		assert.Equal(t, []string{"uid:1000"}, store.owners, "owner set must be unchanged")
	})

	t.Run("ShareProfile denied for non-daemon-owner", func(t *testing.T) {
		_, err := s.ShareProfile(nonOwner, &proto.ShareProfileRequest{Shared: true})
		assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
		assert.False(t, store.shared, "shared flag must be unchanged")
	})

	t.Run("AddOwner allowed for daemon owner", func(t *testing.T) {
		_, err := s.AddOwner(owner, &proto.AddOwnerRequest{Principal: "uid:2000"})
		require.NoError(t, err)
		assert.Equal(t, []string{"uid:1000", "uid:2000"}, store.owners)
	})

	t.Run("ShareProfile allowed for root", func(t *testing.T) {
		_, err := s.ShareProfile(root, &proto.ShareProfileRequest{Shared: true})
		require.NoError(t, err)
		assert.True(t, store.shared)
	})
}

// TestDaemonOwnerAllOwnersUseDefault verifies every daemon owner is authorized
// for the default profile, while a non-owner is denied.
func TestDaemonOwnerAllOwnersUseDefault(t *testing.T) {
	s := &Server{groupResolver: ipcauth.NewDefaultGroupResolver()}
	s.owners = ipcauth.Ownership{Owners: []string{"uid:1000", "uid:1001"}}

	deflt := &profilemanager.Profile{ID: profilemanager.ID(profilemanager.DefaultProfileName), Name: "default"}

	// Both owners may use the default profile.
	require.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(ipcauth.Identity{UID: 1000}), deflt, true))
	require.NoError(t, s.authorizeTargetProfile(ctxWithIdentity(ipcauth.Identity{UID: 1001}), deflt, true))

	// A non-owner is denied the default profile.
	err := s.authorizeTargetProfile(ctxWithIdentity(ipcauth.Identity{UID: 2000}), deflt, true)
	assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
}

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
