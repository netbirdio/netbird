//go:build !ios && !android

package cmd

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func preserveJSONSocketTestState(t *testing.T) {
	t.Helper()

	origJSONSocket := jsonSocket
	origEnableJSONSocket := enableJSONSocket
	origProfilesDisabled := profilesDisabled
	origUpdateSettingsDisabled := updateSettingsDisabled
	origCaptureEnabled := captureEnabled
	origNetworksDisabled := networksDisabled
	origAllowGroups := allowGroups

	t.Cleanup(func() {
		jsonSocket = origJSONSocket
		enableJSONSocket = origEnableJSONSocket
		profilesDisabled = origProfilesDisabled
		updateSettingsDisabled = origUpdateSettingsDisabled
		captureEnabled = origCaptureEnabled
		networksDisabled = origNetworksDisabled
		allowGroups = origAllowGroups
	})
}

// testDaemonCommand returns a fresh command with the daemon flags registered.
// Registering resets the bound globals to their defaults, so they are restored
// on cleanup.
func testDaemonCommand(t *testing.T) *cobra.Command {
	t.Helper()
	preserveJSONSocketTestState(t)

	cmd := &cobra.Command{}
	addDaemonFlags(cmd)
	return cmd
}

func TestJSONSocketFlagsArePositiveEnableOnly(t *testing.T) {
	for _, cmd := range []*cobra.Command{runCmd, installCmd, reconfigureCmd} {
		assert.NotNil(t, cmd.Flags().Lookup("enable-json-socket"), "%s should accept --enable-json-socket", cmd.Name())
		assert.NotNil(t, cmd.Flags().Lookup("json-socket"), "%s should accept --json-socket", cmd.Name())
		assert.Nil(t, cmd.Flags().Lookup("disable-json-socket"), "%s should not accept --disable-json-socket", cmd.Name())
		assert.Equal(t, "false", cmd.Flags().Lookup("enable-json-socket").DefValue, "%s should leave the JSON socket off by default", cmd.Name())
	}
}

func TestDaemonFlagsOnlyOnCommandsThatUseThem(t *testing.T) {
	daemonFlags := []string{"disable-profiles", "disable-update-settings", "enable-capture", "disable-networks", "enable-json-socket", "json-socket", "allow-group"}

	// run reads the flags, install and reconfigure save them into the run arguments.
	for _, cmd := range []*cobra.Command{runCmd, installCmd, reconfigureCmd} {
		for _, name := range daemonFlags {
			assert.NotNil(t, cmd.Flags().Lookup(name), "%s should accept --%s", cmd.Name(), name)
		}
	}

	// The other subcommands act on the installed service and would silently ignore them.
	for _, cmd := range []*cobra.Command{startCmd, stopCmd, restartCmd, svcStatusCmd, uninstallCmd, resetParamsCmd} {
		for _, name := range daemonFlags {
			assert.Nil(t, cmd.Flags().Lookup(name), "%s should not accept --%s", cmd.Name(), name)
			assert.Nil(t, cmd.InheritedFlags().Lookup(name), "%s should not inherit --%s", cmd.Name(), name)
		}
	}

	assert.NotNil(t, startCmd.InheritedFlags().Lookup("service"), "every service subcommand should accept --service")
}

func TestBuildServiceArgumentsDefaultDisablesJSONSocket(t *testing.T) {
	preserveJSONSocketTestState(t)

	enableJSONSocket = false
	jsonSocket = "tcp://127.0.0.1:8080"

	args := buildServiceArguments()

	assert.NotContains(t, args, "--enable-json-socket")
	assert.NotContains(t, args, "--json-socket")
}

func TestBuildServiceArgumentsIncludesJSONSocketWhenEnabled(t *testing.T) {
	preserveJSONSocketTestState(t)

	enableJSONSocket = true
	jsonSocket = "tcp://127.0.0.1:8080"

	args := buildServiceArguments()

	enableIndex := indexOfArg(args, "--enable-json-socket")
	jsonIndex := indexOfArg(args, "--json-socket")
	require.NotEqual(t, -1, enableIndex)
	require.NotEqual(t, -1, jsonIndex)
	require.Less(t, enableIndex, jsonIndex)
	require.Less(t, jsonIndex+1, len(args))
	assert.Equal(t, "tcp://127.0.0.1:8080", args[jsonIndex+1])
}

func TestJSONSocketWithoutEnableValidation(t *testing.T) {
	cmd := testDaemonCommand(t)

	require.NoError(t, cmd.Flags().Set("json-socket", "tcp://127.0.0.1:8080"))

	err := validateJSONSocketFlags(cmd)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--enable-json-socket")
}

func TestJSONSocketWithEnableValidation(t *testing.T) {
	cmd := testDaemonCommand(t)

	require.NoError(t, cmd.Flags().Set("enable-json-socket", "true"))
	require.NoError(t, cmd.Flags().Set("json-socket", "tcp://127.0.0.1:8080"))

	assert.NoError(t, validateJSONSocketFlags(cmd))
}

func TestJSONSocketServiceParamsPersistEnableAndAddress(t *testing.T) {
	preserveJSONSocketTestState(t)

	enableJSONSocket = true
	jsonSocket = "tcp://127.0.0.1:8080"

	params := currentServiceParams()
	require.True(t, params.EnableJSONSocket)
	require.Equal(t, "tcp://127.0.0.1:8080", params.JSONSocket)

	enableJSONSocket = false
	jsonSocket = defaultJSONSocket
	applyServiceParams(testServiceEnvCommand(), params)

	assert.True(t, enableJSONSocket)
	assert.Equal(t, "tcp://127.0.0.1:8080", jsonSocket)
}

func TestRemoveStaleUnixSocketDoesNotRemoveRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netbird-http.sock")
	require.NoError(t, os.WriteFile(path, []byte("not a socket"), 0600))

	removeStaleUnixSocket(path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("not a socket"), data)
}

func TestRemoveStaleUnixSocketRemovesSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not available on Windows")
	}

	path := filepath.Join(t.TempDir(), "netbird-http.sock")
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	require.NoError(t, err)
	listener.SetUnlinkOnClose(false)
	require.NoError(t, listener.Close())

	_, err = os.Lstat(path)
	require.NoError(t, err, "test setup must leave a stale Unix socket path")

	removeStaleUnixSocket(path)

	_, err = os.Lstat(path)
	assert.True(t, os.IsNotExist(err), "expected stale Unix socket to be removed, got %v", err)
}

func TestRemoveStaleUnixSocketDoesNotRemoveLiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not available on Windows")
	}

	path := filepath.Join(t.TempDir(), "netbird-http.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer listener.Close()

	removeStaleUnixSocket(path)

	_, err = os.Lstat(path)
	assert.NoError(t, err, "expected live Unix socket to be preserved")
}

func testServiceEnvCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("service-env", nil, "")
	return cmd
}

func indexOfArg(args []string, arg string) int {
	for i, candidate := range args {
		if candidate == arg {
			return i
		}
	}
	return -1
}
