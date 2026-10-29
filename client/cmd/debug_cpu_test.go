package cmd

import (
	"bytes"
	"context"
	"os/user"
	"strings"
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
		// Set appends to a slice flag and would parse the "[a,b]" default
		// text as elements, so slices are replaced instead.
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			var def []string
			if trimmed := strings.Trim(f.DefValue, "[]"); trimmed != "" {
				def = strings.Split(trimmed, ",")
			}
			_ = sv.Replace(def)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	cmd.Flags().VisitAll(reset)
	cmd.PersistentFlags().VisitAll(reset)
	// Commands pin their writers to the buffer of the run that first used
	// them, so a later run would print into the old buffer.
	cmd.SetOut(nil)
	cmd.SetErr(nil)
	for _, sub := range cmd.Commands() {
		resetFlags(sub)
	}
}

// TestResetFlagsSliceDefault guards against Set("[]") on slice flags, which
// stores a literal "[]" element instead of the empty default.
func TestResetFlagsSliceDefault(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	var env, withDefault []string
	cmd.Flags().StringSliceVar(&env, "env", nil, "")
	cmd.Flags().StringSliceVar(&withDefault, "names", []string{"a", "b"}, "")
	require.NoError(t, cmd.Flags().Parse([]string{"--env", "K=V", "--names", "c"}))

	resetFlags(cmd)

	assert.Empty(t, env, "slice flag with no default must reset to empty")
	assert.Equal(t, []string{"a", "b"}, withDefault, "slice flag must reset to its default")
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

// TestDebugForKeepsRunningCPUProfile covers `debug for` started while a
// profile from `debug cpu start` is running: it must say so, leave the
// profile alone, and still create the bundle.
func TestDebugForKeepsRunningCPUProfile(t *testing.T) {
	addr := startDebugTestDaemon(t)

	_, err := runDebugCmd(addr, "cpu", "start")
	require.NoError(t, err)

	out, err := runDebugCmd(addr, "for", "1s", "-S=false", "--no-updown")
	require.NoError(t, err, "output: %s", out)
	assert.Contains(t, out, "CPU profiling is already running", "the conflict must be explained")
	assert.NotContains(t, out, "rpc error", "the raw RPC error must not reach the user")
	assert.Contains(t, out, "Local file:", "the bundle must still be created")

	_, err = runDebugCmd(addr, "cpu", "stop")
	assert.NoError(t, err, "the profile started by the user must still be running")
}

func TestDebugForNoUpDown(t *testing.T) {
	addr := startDebugTestDaemon(t)

	out, err := runDebugCmd(addr, "for", "1s", "-S=false", "--no-updown")
	require.NoError(t, err, "output: %s", out)
	assert.NotContains(t, out, "netbird down", "--no-updown must not bring the daemon down")
	assert.NotContains(t, out, "netbird up", "--no-updown must not bring the daemon up")
	assert.Contains(t, out, "Local file:", "the bundle must still be created")
}
