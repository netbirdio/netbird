package cmd

import (
	"os/user"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Omitting --owner is only allowed where the invoking user can be recovered.
// Everywhere else the admin names the owner rather than having one guessed.
func TestDefaultClaimOwner(t *testing.T) {
	got, err := defaultClaimOwner()

	switch {
	case runtime.GOOS == "windows":
		require.Error(t, err, "Windows keeps no record of who asked for elevation")
		assert.Contains(t, err.Error(), "--owner")
	case profilemanager.IsPlainRoot():
		require.Error(t, err, "plain root has no invoking user to act for")
		assert.Contains(t, err.Error(), "--owner")
	default:
		require.NoError(t, err)
		_, ok := ipcauth.ParsePrincipal(got)
		assert.True(t, ok, "default owner %q must be a principal", got)
	}
}

// A user shaped like InvokingUser's fallback for a UID with no account entry,
// where the username is the numeric UID, must still map to that UID's principal.
func TestUserPrincipal_UnmappedUID(t *testing.T) {
	got, err := userPrincipal(&user.User{Username: "4242", Uid: "4242", Gid: "4242"})
	require.NoError(t, err)
	assert.Equal(t, "uid:4242", got)
}

func TestClaimOwner_PassesPrincipalThrough(t *testing.T) {
	for _, owner := range []string{"uid:4242", "sid:S-1-5-21-1-2-3-4242"} {
		got, err := claimOwner(owner)
		require.NoError(t, err)
		assert.Equal(t, owner, got, "a principal must be sent unchanged")
	}
}

func TestClaimOwner_ResolvesAccountName(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err)
	want, ok := profilemanager.PrincipalForUser(u)
	require.True(t, ok)

	got, err := claimOwner(u.Username)
	require.NoError(t, err)
	assert.Equal(t, want, got, "an account name must resolve to its principal")
}

func TestClaimOwner_RefusesUnknownAccountName(t *testing.T) {
	_, err := claimOwner("no-such-account-here")
	require.Error(t, err)
}
