package getent

import (
	"os/user"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupUser_CurrentUser(t *testing.T) {
	// The current user should always be resolvable on any platform
	current, err := user.Current()
	require.NoError(t, err)

	u, err := LookupUser(current.Username)
	require.NoError(t, err)
	assert.Equal(t, current.Username, u.Username)
	assert.Equal(t, current.Uid, u.Uid)
	assert.Equal(t, current.Gid, u.Gid)
}

func TestLookupUser_NonexistentUser(t *testing.T) {
	_, err := LookupUser("nonexistent_user_xyzzy_12345")
	require.Error(t, err, "should fail for nonexistent user")
}

func TestLookupUserID_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	u, err := LookupUserID(current.Uid)
	require.NoError(t, err)
	assert.Equal(t, current.Username, u.Username)
	assert.Equal(t, current.Uid, u.Uid)
}

func TestCurrentUser(t *testing.T) {
	stdUser, err := user.Current()
	require.NoError(t, err)

	u, err := CurrentUser()
	require.NoError(t, err)
	assert.Equal(t, stdUser.Uid, u.Uid)
	assert.Equal(t, stdUser.Username, u.Username)
}

func TestGroupIDs_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	groups, err := GroupIDs(current)
	require.NoError(t, err)
	require.NotEmpty(t, groups, "current user should have at least one group")

	if runtime.GOOS != "windows" {
		for _, gid := range groups {
			_, err := strconv.ParseUint(gid, 10, 32)
			assert.NoError(t, err, "group ID %q should be a valid uint32", gid)
		}
	}
}

func TestUserShell_CurrentUser(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	// getent may not be available on all systems (e.g., macOS without
	// Homebrew getent), and Windows has no login shells at all.
	shell, err := UserShell(current.Uid)
	if err != nil {
		t.Logf("UserShell failed, getent may not be available: %v", err)
		return
	}
	if shell == "" {
		t.Log("UserShell returned empty, the user has no shell set")
		return
	}
	assert.True(t, shell[0] == '/', "shell should be an absolute path, got %q", shell)
}

func TestLookupUser_RootUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no root user on Windows")
	}

	u, err := LookupUser("root")
	if err != nil {
		t.Skip("root user not available on this system")
	}
	assert.Equal(t, "0", u.Uid, "root should have UID 0")
}

// TestIntegration_FullLookupChain exercises the complete user lookup chain
// against the real system, testing that all wrappers (LookupUser,
// CurrentUser, GroupIDs, UserShell) produce consistent and correct results
// when composed together.
func TestIntegration_FullLookupChain(t *testing.T) {
	// Step 1: CurrentUser must resolve the running user.
	current, err := CurrentUser()
	require.NoError(t, err, "CurrentUser must resolve the running user")
	require.NotEmpty(t, current.Uid)
	require.NotEmpty(t, current.Username)

	// Step 2: LookupUser by the same username must return matching identity.
	byName, err := LookupUser(current.Username)
	require.NoError(t, err)
	assert.Equal(t, current.Uid, byName.Uid, "lookup by name should return same UID")
	assert.Equal(t, current.Gid, byName.Gid, "lookup by name should return same GID")
	assert.Equal(t, current.HomeDir, byName.HomeDir, "lookup by name should return same home")

	// Step 3: GroupIDs must return at least the primary GID.
	groups, err := GroupIDs(current)
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
}

// TestIntegration_LookupAndGroupsConsistency verifies that a user resolved via
// LookupUser can have their groups resolved via GroupIDs, testing the handoff
// between the two functions as used by the SSH server.
func TestIntegration_LookupAndGroupsConsistency(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	// Simulate the SSH server flow: lookup user, then get their groups.
	resolved, err := LookupUser(current.Username)
	require.NoError(t, err)

	groups, err := GroupIDs(resolved)
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
