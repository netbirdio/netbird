package cmd

import (
	"context"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestDebugCPUStartStop(t *testing.T) {
	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	origDaemonAddr := daemonAddr
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.ConfigDirOverride = tempDir

	currUser, err := user.Current()
	require.NoError(t, err)
	sm := profilemanager.ServiceManager{}
	created, err := sm.AddProfile("test1", currUser.Username)
	require.NoError(t, err)
	require.NoError(t, sm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       created.ID,
		Username: currUser.Username,
	}))

	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.ConfigDirOverride = ""
		daemonAddr = origDaemonAddr
	})

	ctx := internal.CtxInitState(context.Background())
	_, lis := startClientDaemon(t, ctx, "", tempDir+"/config.json")
	addr := "tcp://" + lis.Addr().String()

	run := func(args ...string) error {
		daemonAddr = addr
		rootCmd.SetArgs(append([]string{"debug", "cpu"}, append(args, "--daemon-addr", addr, "--log-file", "")...))
		return rootCmd.Execute()
	}

	require.Error(t, run("stop"), "stop without a running profile must fail")
	require.NoError(t, run("start"))
	assert.Error(t, run("start"), "second start must be rejected while profiling")
	require.NoError(t, run("stop"))
	assert.Error(t, run("stop"), "second stop must be rejected")
	assert.NoError(t, run("start"), "profiling can be started again after a stop")
	assert.NoError(t, run("stop"))
}
