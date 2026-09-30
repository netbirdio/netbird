package cmd

import (
	"bytes"
	"context"
	"os/user"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// startDebugTestDaemon starts an in-process daemon with an isolated profile
// directory and returns the address the CLI should dial.
func startDebugTestDaemon(t *testing.T) string {
	t.Helper()

	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	origConfigDirOverride := profilemanager.ConfigDirOverride
	origDaemonAddr := daemonAddr
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.ConfigDirOverride = origConfigDirOverride
		daemonAddr = origDaemonAddr
	})

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

	ctx, cancel := context.WithCancel(internal.CtxInitState(context.Background()))
	srv, lis := startClientDaemon(t, ctx, "", tempDir+"/config.json")
	t.Cleanup(func() {
		cancel()
		srv.Stop()
	})

	return "tcp://" + lis.Addr().String()
}

// runDebugCmd runs `netbird debug <args>` against the daemon at addr and
// returns everything the command printed.
func runDebugCmd(addr string, args ...string) (string, error) {
	daemonAddr = addr
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append(append([]string{"debug"}, args...), "--daemon-addr", addr, "--log-file", ""))
	err := rootCmd.Execute()
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetArgs(nil)
	resetFlags(rootCmd)
	return out.String(), err
}

// resetFlags puts every flag of the command and its subcommands back to its
// default so a value parsed in one run does not leak into the next in-process
// execution.
func resetFlags(cmd *cobra.Command) {
	reset := func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	}
	cmd.Flags().VisitAll(reset)
	cmd.PersistentFlags().VisitAll(reset)
	for _, sub := range cmd.Commands() {
		resetFlags(sub)
	}
}

func TestDebugCPUStartStop(t *testing.T) {
	addr := startDebugTestDaemon(t)

	run := func(args ...string) error {
		_, err := runDebugCmd(addr, append([]string{"cpu"}, args...)...)
		return err
	}

	require.Error(t, run("stop"), "stop without a running profile must fail")
	require.NoError(t, run("start"))
	assert.Error(t, run("start"), "second start must be rejected while profiling")
	require.NoError(t, run("stop"))
	assert.Error(t, run("stop"), "second stop must be rejected")
	assert.NoError(t, run("start"), "profiling can be started again after a stop")
	assert.NoError(t, run("stop"))
}

func TestDebugForNoUpDown(t *testing.T) {
	addr := startDebugTestDaemon(t)

	out, err := runDebugCmd(addr, "for", "1s", "-S=false", "--no-updown")
	require.NoError(t, err, "output: %s", out)
	assert.NotContains(t, out, "netbird down", "--no-updown must not bring the daemon down")
	assert.NotContains(t, out, "netbird up", "--no-updown must not bring the daemon up")
	assert.Contains(t, out, "Local file:", "the bundle must still be created")
}
