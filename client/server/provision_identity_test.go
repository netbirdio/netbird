package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// The daemon provisions the peer's identity and persists it, because a key that
// stayed in memory would come back different on the next start and register a
// second peer. Provisioning is idempotent: a profile that already has an
// identity keeps the one on disk.
func TestProvisionProfileIdentity(t *testing.T) {
	origDir := profilemanager.DefaultConfigPathDir
	origPath := profilemanager.DefaultConfigPath
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.DefaultConfigPath = origPath
	})

	dir := t.TempDir()
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

	activeProf := &profilemanager.ActiveProfileState{ID: "default"}
	sm := profilemanager.NewServiceManager("")

	t.Run("a profile with no file is provisioned and written", func(t *testing.T) {
		_, err := os.Stat(profilemanager.DefaultConfigPath)
		require.True(t, os.IsNotExist(err), "the fixture starts without a config file")

		config, existed, err := provisionProfileIdentity(sm, activeProf)
		require.NoError(t, err)
		require.False(t, existed, "the file was reported as pre-existing")
		require.NotEmpty(t, config.PrivateKey)

		stored, err := profilemanager.GetExistingConfig(profilemanager.DefaultConfigPath)
		require.NoError(t, err, "provisioning did not write the config out")
		require.Equal(t, config.PrivateKey, stored.PrivateKey, "the persisted identity is not the one returned")
		require.NotEmpty(t, stored.SSHKey)
	})

	t.Run("a second call keeps the identity on disk", func(t *testing.T) {
		before, err := profilemanager.GetExistingConfig(profilemanager.DefaultConfigPath)
		require.NoError(t, err)

		config, existed, err := provisionProfileIdentity(sm, activeProf)
		require.NoError(t, err)
		require.True(t, existed)
		require.Equal(t, before.PrivateKey, config.PrivateKey, "provisioning minted a second identity")

		after, err := profilemanager.GetExistingConfig(profilemanager.DefaultConfigPath)
		require.NoError(t, err)
		require.Equal(t, before.PrivateKey, after.PrivateKey, "provisioning rewrote the stored identity")
	})
}

// A profile created since the ID-keyed layout lives in the shared profiles
// directory, not in a per-username one. Provisioning has to read the identity
// already in that file rather than mint a new one somewhere else.
func TestProvisionProfileIdentity_SharedProfileDirectory(t *testing.T) {
	origDir := profilemanager.DefaultConfigPathDir
	origPath := profilemanager.DefaultConfigPath
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.DefaultConfigPath = origPath
	})

	dir := t.TempDir()
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

	sm := profilemanager.NewServiceManager("")
	caller := unprivilegedIdentity()
	created, err := sm.AddProfile("work", &caller)
	require.NoError(t, err)

	stored, err := profilemanager.GetExistingConfig(created.Path)
	require.NoError(t, err)
	require.NotEmpty(t, stored.PrivateKey, "the fixture profile has no identity")

	config, existed, err := provisionProfileIdentity(sm, &profilemanager.ActiveProfileState{ID: created.ID})
	require.NoError(t, err)
	require.True(t, existed, "the profile's own file was not found")
	require.Equal(t, stored.PrivateKey, config.PrivateKey, "provisioning minted a second identity")

	_, err = os.Stat(filepath.Join(dir, created.ID.String()+".json"))
	require.True(t, os.IsNotExist(err), "a config was written outside the profile's directory")
}
