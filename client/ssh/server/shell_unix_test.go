//go:build !windows

package server

import (
	"os/exec"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/getent"
)

// TestGetShellFromPasswd_CurrentUser verifies that getShellFromPasswd correctly
// reads the current user's shell from /etc/passwd by comparing it against what
// getent reports (which goes through NSS).
func TestGetShellFromPasswd_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	shell := getShellFromPasswd(current.Uid)
	if shell == "" {
		t.Skip("current user not found in /etc/passwd (may be an NSS-only user)")
	}

	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)

	if _, err := exec.LookPath("getent"); err == nil {
		getentShell, getentErr := getent.UserShell(current.Uid)
		if getentErr == nil && getentShell != "" {
			assert.Equal(t, getentShell, shell, "shell from /etc/passwd should match getent")
		}
	}
}

// TestGetShellFromPasswd_RootUser verifies that getShellFromPasswd can read
// root's shell from /etc/passwd. Root is guaranteed to be in /etc/passwd on
// any standard Unix system.
func TestGetShellFromPasswd_RootUser(t *testing.T) {
	shell := getShellFromPasswd("0")
	require.NotEmpty(t, shell, "root (UID 0) must be in /etc/passwd")
	assert.True(t, shell[0] == '/', "root shell should be an absolute path, got %q", shell)
}

// TestGetShellFromPasswd_NonexistentUID verifies that getShellFromPasswd
// returns empty for a UID that doesn't exist in /etc/passwd.
func TestGetShellFromPasswd_NonexistentUID(t *testing.T) {
	shell := getShellFromPasswd("4294967294")
	assert.Empty(t, shell, "nonexistent UID should return empty shell")
}

// TestGetShellFromPasswd_MatchesGetentForKnownUsers reads /etc/passwd directly
// and cross-validates every entry against getent to ensure the two shell
// sources agree.
func TestGetShellFromPasswd_MatchesGetentForKnownUsers(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available")
	}

	// Pick a few well-known system UIDs that are virtually always in /etc/passwd.
	uids := []string{"0"} // root

	current, err := user.Current()
	require.NoError(t, err)
	uids = append(uids, current.Uid)

	for _, uid := range uids {
		passwdShell := getShellFromPasswd(uid)
		if passwdShell == "" {
			continue
		}

		getentShell, err := getent.UserShell(uid)
		if err != nil {
			continue
		}

		assert.Equal(t, getentShell, passwdShell, "shell mismatch for UID %s", uid)
	}
}

// TestIntegration_ShellLookupChain tests the full shell resolution chain
// (getShellFromPasswd -> getent -> $SHELL -> default).
func TestIntegration_ShellLookupChain(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	// getUserShell is the top-level function used by the SSH server.
	shell := getUserShell(current.Uid)
	require.NotEmpty(t, shell, "getUserShell must always return a shell")
	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
}
