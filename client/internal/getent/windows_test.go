//go:build windows

package getent

import (
	"errors"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errNoneMapped stands in for the ERROR_NONE_MAPPED os/user returns on an
// Entra ID joined machine, where the account's domain does not resolve on its
// own but the account does.
var errNoneMapped = errors.New("no mapping between account names and security IDs was done")

func failStdLookups(t *testing.T) {
	t.Helper()
	origLookup, origLookupID := stdLookup, stdLookupID
	stdLookup = func(string) (*user.User, error) { return nil, errNoneMapped }
	stdLookupID = func(string) (*user.User, error) { return nil, errNoneMapped }
	t.Cleanup(func() {
		stdLookup, stdLookupID = origLookup, origLookupID
	})
}

func TestLookupUser_FallsBackWhenOSUserFails(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	failStdLookups(t)

	u, err := LookupUser(current.Username)
	require.NoError(t, err)
	assert.Equal(t, current.Uid, u.Uid, "fallback should resolve the same SID")
	assert.Equal(t, current.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, current.HomeDir, u.HomeDir, "fallback should read the profile path")
	assert.Empty(t, u.Gid, "fallback does not resolve a primary group")
}

func TestLookupUserID_FallsBackWhenOSUserFails(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	failStdLookups(t)

	u, err := LookupUserID(current.Uid)
	require.NoError(t, err)
	assert.Equal(t, current.Uid, u.Uid, "fallback should keep the SID")
	assert.Equal(t, current.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, current.HomeDir, u.HomeDir, "fallback should read the profile path")
}

func TestLookupUser_FallbackKeepsOSUserErrorForUnknownAccount(t *testing.T) {
	failStdLookups(t)

	_, err := LookupUser("nonexistent_user_xyzzy_12345")
	require.ErrorIs(t, err, errNoneMapped, "an account LSA cannot map either should report the os/user error")
}

func TestLookupUserID_FallbackRejectsNonUserSID(t *testing.T) {
	failStdLookups(t)

	// S-1-5-32-544 is BUILTIN\Administrators, a group rather than a user.
	_, err := LookupUserID("S-1-5-32-544")
	require.ErrorIs(t, err, errNoneMapped, "a group SID must not resolve as a user")
}

func TestLookupUserID_FallbackRejectsMalformedSID(t *testing.T) {
	failStdLookups(t)

	_, err := LookupUserID("not-a-sid")
	require.ErrorIs(t, err, errNoneMapped)
}
