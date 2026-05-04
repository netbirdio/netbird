package server

import (
	"os/user"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupWithGetent_CurrentUser(t *testing.T) {
	// The current user should always be resolvable on any platform
	current, err := user.Current()
	require.NoError(t, err)

	u, err := lookupWithGetent(current.Username)
	require.NoError(t, err)
	assert.Equal(t, current.Username, u.Username)
	assert.Equal(t, current.Uid, u.Uid)
	assert.Equal(t, current.Gid, u.Gid)
}

func TestLookupWithGetent_NonexistentUser(t *testing.T) {
	_, err := lookupWithGetent("nonexistent_user_xyzzy_12345")
	require.Error(t, err, "should fail for nonexistent user")
}

func TestCurrentUserWithGetent(t *testing.T) {
	stdUser, err := user.Current()
	require.NoError(t, err)

	u, err := currentUserWithGetent()
	require.NoError(t, err)
	assert.Equal(t, stdUser.Uid, u.Uid)
	assert.Equal(t, stdUser.Username, u.Username)
}

func TestGroupIdsWithFallback_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	groups, err := groupIdsWithFallback(current)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "current user should have at least one group")

	if runtime.GOOS != "windows" {
		for _, gid := range groups {
			_, err := strconv.ParseUint(gid, 10, 32)
			assert.NoError(t, err, "group ID %q should be a valid uint32", gid)
		}
	}
}

func TestGetShellFromGetent_CurrentUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows stub always returns empty, which is correct
		shell := getShellFromGetent("1000")
		assert.Empty(t, shell, "Windows stub should return empty")
		return
	}

	current, err := user.Current()
	require.NoError(t, err)

	// getent may not be available on all systems (e.g., macOS without Homebrew getent)
	shell := getShellFromGetent(current.Uid)
	if shell == "" {
		t.Log("getShellFromGetent returned empty, getent may not be available")
		return
	}
	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
}

func TestLookupWithGetent_RootUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no root user on Windows")
	}

	u, err := lookupWithGetent("root")
	if err != nil {
		t.Skip("root user not available on this system")
	}
	assert.Equal(t, "0", u.Uid, "root should have UID 0")
}

// TestIntegration_FullLookupChain exercises the complete user lookup chain
// against the real system, testing that all wrappers (lookupWithGetent,
// currentUserWithGetent, groupIdsWithFallback, getShellFromGetent) produce
// consistent and correct results when composed together.
func TestIntegration_FullLookupChain(t *testing.T) {
	// Step 1: currentUserWithGetent must resolve the running user.
	current, err := currentUserWithGetent()
	require.NoError(t, err, "currentUserWithGetent must resolve the running user")
	require.NotEmpty(t, current.Uid)
	require.NotEmpty(t, current.Username)

	// Step 2: lookupWithGetent by the same username must return matching identity.
	byName, err := lookupWithGetent(current.Username)
	require.NoError(t, err)
	assert.Equal(t, current.Uid, byName.Uid, "lookup by name should return same UID")
	assert.Equal(t, current.Gid, byName.Gid, "lookup by name should return same GID")
	assert.Equal(t, current.HomeDir, byName.HomeDir, "lookup by name should return same home")

	// Step 3: groupIdsWithFallback must return at least the primary GID.
	groups, err := groupIdsWithFallback(current)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "user must have at least one group")

	foundPrimary := false
	for _, gid := range groups {
		if runtime.GOOS != "windows" {
			_, err := strconv.ParseUint(gid, 10, 32)
			require.NoError(t, err, "group ID %q must be a valid uint32", gid)
		}
		if gid == current.Gid {
			foundPrimary = true
		}
	}
	assert.True(t, foundPrimary, "primary GID %s should appear in supplementary groups", current.Gid)

	// Step 4: getShellFromGetent should either return a valid shell path or empty
	// (empty is OK when getent is not available, e.g. macOS without Homebrew getent).
	if runtime.GOOS != "windows" {
		shell := getShellFromGetent(current.Uid)
		if shell != "" {
			assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
		}
	}
}

// TestIntegration_LookupAndGroupsConsistency verifies that a user resolved via
// lookupWithGetent can have their groups resolved via groupIdsWithFallback,
// testing the handoff between the two functions as used by the SSH server.
func TestIntegration_LookupAndGroupsConsistency(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	// Simulate the SSH server flow: lookup user, then get their groups.
	resolved, err := lookupWithGetent(current.Username)
	require.NoError(t, err)

	groups, err := groupIdsWithFallback(resolved)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "resolved user must have groups")

	// On Unix, all returned GIDs must be valid numeric values.
	// On Windows, group IDs are SIDs (e.g., "S-1-5-32-544").
	if runtime.GOOS != "windows" {
		for _, gid := range groups {
			_, err := strconv.ParseUint(gid, 10, 32)
			assert.NoError(t, err, "group ID %q should be numeric", gid)
		}
	}
}

// TestIntegration_ShellLookupChain tests the full shell resolution chain
// (getShellFromPasswd -> getShellFromGetent -> $SHELL -> default) on Unix.
func TestIntegration_ShellLookupChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell lookup not applicable on Windows")
	}

	current, err := user.Current()
	require.NoError(t, err)

	// getUserShell is the top-level function used by the SSH server.
	shell := getUserShell(current.Uid)
	require.NotEmpty(t, shell, "getUserShell must always return a shell")
	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
}
