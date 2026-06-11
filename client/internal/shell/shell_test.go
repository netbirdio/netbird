package shell

import (
	"os/user"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_ShellLookupChain tests the full shell resolution chain
// (getShellFromPasswd -> getShellFromGetent -> $SHELL -> default) on Unix.
func TestIntegration_ShellLookupChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell lookup not applicable on Windows")
	}

	current, err := user.Current()
	require.NoError(t, err)

	// getUserShell is the top-level function used by the SSH server.
	shell := GetUserShell(current.Uid)
	require.NotEmpty(t, shell, "getUserShell must always return a shell")
	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
}
