package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"

	"github.com/netbirdio/netbird/client/internal/filedrop"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func fileDropTestServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()

	prevOverride := profilemanager.ConfigDirOverride
	prevPathDir := profilemanager.DefaultConfigPathDir
	prevPath := profilemanager.DefaultConfigPath
	prevActive := profilemanager.ActiveProfileStatePath
	t.Cleanup(func() {
		profilemanager.ConfigDirOverride = prevOverride
		profilemanager.DefaultConfigPathDir = prevPathDir
		profilemanager.DefaultConfigPath = prevPath
		profilemanager.ActiveProfileStatePath = prevActive
	})

	profilemanager.ConfigDirOverride = dir
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")

	sm := profilemanager.NewServiceManager(profilemanager.DefaultConfigPath)
	require.NoError(t, sm.SetActiveProfileStateToDefault())

	return &Server{profileManager: sm}
}

func callerContext(t *testing.T) context.Context {
	t.Helper()

	id, err := ipcauth.CurrentProcessIdentity()
	require.NoError(t, err)

	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: ipcauth.AuthInfo{Identity: id},
	})
}

func TestFileDropSetSettingsKeepsTheModeWhenTheDestinationIsRefused(t *testing.T) {
	s := fileDropTestServer(t)
	ctx := callerContext(t)

	mgr, err := s.fileDropManager(ctx)
	require.NoError(t, err)
	require.NoError(t, mgr.Policy().Set(filedrop.Policy{Mode: filedrop.ModeOff}))

	bound := 0
	mgr.Policy().SetChangeHandler(func() { bound++ })

	// A path that is not a directory is refused by validateFileDropDestination
	// whatever the caller's privileges, so the refusal is the same everywhere.
	notADir := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))

	_, err = s.FileDropSetSettings(ctx, &proto.FileDropSetSettingsRequest{
		Mode:           proto.FileDropMode(filedrop.ModeAutoAccept),
		DestinationDir: notADir,
	})
	require.Error(t, err, "a destination that is not a directory must be refused")

	assert.Equal(t, filedrop.ModeOff, mgr.Policy().Get().Mode,
		"the refused request must not leave the mode switched to auto-accept")
	assert.False(t, mgr.Policy().Receiving(), "the receiver must not have been turned on")
	assert.Zero(t, bound, "the change handler must not have fired")
}

func TestFileDropSetSettingsAppliesModeAndDestinationTogether(t *testing.T) {
	s := fileDropTestServer(t)
	ctx := callerContext(t)

	mgr, err := s.fileDropManager(ctx)
	require.NoError(t, err)
	require.NoError(t, mgr.Policy().Set(filedrop.Policy{Mode: filedrop.ModeOff}))

	dest := t.TempDir()
	_, err = s.FileDropSetSettings(ctx, &proto.FileDropSetSettingsRequest{
		Mode:           proto.FileDropMode(filedrop.ModeAsk),
		DestinationDir: dest,
	})
	require.NoError(t, err)

	assert.Equal(t, filedrop.ModeAsk, mgr.Policy().Get().Mode)
	assert.Equal(t, dest, mgr.Policy().DestinationDir())
}
