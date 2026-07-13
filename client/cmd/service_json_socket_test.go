//go:build !ios && !android

package cmd

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func preserveJSONSocketTestState(t *testing.T) {
	t.Helper()

	origJSONSocket := jsonSocket
	origEnableJSONSocket := enableJSONSocket
	origChanged := map[string]bool{}
	serviceCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		origChanged[flag.Name] = flag.Changed
	})

	t.Cleanup(func() {
		jsonSocket = origJSONSocket
		enableJSONSocket = origEnableJSONSocket
		serviceCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
			flag.Changed = origChanged[flag.Name]
		})
	})
}

func TestJSONSocketFlagsArePositiveEnableOnly(t *testing.T) {
	assert.NotNil(t, serviceCmd.PersistentFlags().Lookup("enable-json-socket"))
	assert.NotNil(t, serviceCmd.PersistentFlags().Lookup("json-socket"))
	assert.Nil(t, serviceCmd.PersistentFlags().Lookup("disable-json-socket"))
	assert.Equal(t, "false", serviceCmd.PersistentFlags().Lookup("enable-json-socket").DefValue)
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
	preserveJSONSocketTestState(t)

	enableJSONSocket = false
	require.NoError(t, serviceCmd.PersistentFlags().Set("json-socket", "tcp://127.0.0.1:8080"))

	err := validateJSONSocketFlags()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--enable-json-socket")
}

func TestJSONSocketWithEnableValidation(t *testing.T) {
	preserveJSONSocketTestState(t)

	require.NoError(t, serviceCmd.PersistentFlags().Set("enable-json-socket", "true"))
	require.NoError(t, serviceCmd.PersistentFlags().Set("json-socket", "tcp://127.0.0.1:8080"))

	assert.NoError(t, validateJSONSocketFlags())
}

func TestJSONSocketServiceParamsPersistEnableAndAddress(t *testing.T) {
	preserveJSONSocketTestState(t)
	serviceCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		flag.Changed = false
	})

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
