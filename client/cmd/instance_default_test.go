package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// T-DEF-01, consumer side: the service registration and the flag defaults of the
// default installation are the v0.81.5 values.
func TestDefaultServiceAndFlagsV0815(t *testing.T) {
	wantService, wantAddr, wantLog := "netbird", "unix:///var/run/netbird.sock", "/var/log/netbird/client.log"
	if runtime.GOOS == "windows" {
		wantService = "Netbird"
		wantAddr = "npipe://netbird"
		wantLog = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird", "client.log")
	}

	assert.Equal(t, wantService, rootCmd.PersistentFlags().Lookup("service").DefValue, "service flag default")
	assert.Equal(t, wantAddr, rootCmd.PersistentFlags().Lookup("daemon-addr").DefValue, "daemon-addr flag default")
	assert.Equal(t, "["+wantLog+"]", rootCmd.PersistentFlags().Lookup("log-file").DefValue, "log-file flag default")
	assert.Equal(t, "unix:///var/run/netbird-http.sock", serviceCmd.PersistentFlags().Lookup("json-socket").DefValue, "json-socket flag default")

	cfg, err := newSVCConfig()
	require.NoError(t, err)
	assert.Equal(t, "Netbird", cfg.DisplayName, "service display name")
	assert.Equal(t, "NetBird mesh network client", cfg.Description, "service description")
}
