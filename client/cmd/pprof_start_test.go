//go:build !ios && !android

package cmd

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// SBS-NET-05: the pprof listener starts once the installation is resolved, so
// a named installation listens on its own derived address.
func TestPprofStartsAfterInstanceResolution(t *testing.T) {
	resetInstanceState(t)
	saved := startPprof
	t.Cleanup(func() {
		startPprof = saved
		rootCmd.SetArgs(nil)
	})

	var addrs []string
	startPprof = func() { addrs = append(addrs, instance.Current().PprofAddr()) }

	rootCmd.SetArgs([]string{"version"})
	require.NoError(t, rootCmd.Execute())
	assert.Equal(t, []string{instance.Default().PprofAddr()}, addrs, "the default installation keeps its address")

	if runtime.GOOS != "windows" {
		return
	}
	addrs = nil
	rootCmd.SetArgs([]string{"--instance", "acme", "version"})
	require.NoError(t, rootCmd.Execute())
	assert.Equal(t, []string{"localhost:6985"}, addrs, "a named installation listens on its derived address")
}
