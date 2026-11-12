//go:build windows

package getent

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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

// localAdministrator returns the built-in local Administrator as os/user sees
// it. The tests use it instead of the current user because CI runs them as
// SYSTEM, which user.Current names after the machine account, a name LSA
// cannot look up.
func localAdministrator(t *testing.T) *user.User {
	t.Helper()
	host, err := windows.ComputerName()
	require.NoError(t, err)

	machine, _, sidType, err := windows.LookupSID("", host)
	require.NoError(t, err, "look up the local account domain")
	if sidType != windows.SidTypeDomain {
		t.Skipf("%s does not name a local account domain (type %d), as on a domain controller", host, sidType)
	}

	// RID 500 is the built-in Administrator, present even when disabled or renamed.
	u, err := user.LookupId(machine.String() + "-500")
	require.NoError(t, err, "os/user must resolve the local Administrator")
	return u
}

// profileOf is the home directory the fallback should report for uid. It is
// empty for an account that never signed in, where os/user guesses a path
// instead, so the tests compare against this rather than os/user's HomeDir.
func profileOf(uid string) string {
	dir, err := profileHomeDir(uid)
	if err != nil {
		return ""
	}
	return dir
}

func TestLookupUser_FallsBackWhenOSUserFails(t *testing.T) {
	admin := localAdministrator(t)
	failStdLookups(t)

	u, err := LookupUser(admin.Username)
	require.NoError(t, err)
	assert.Equal(t, admin.Uid, u.Uid, "fallback should resolve the same SID")
	assert.Equal(t, admin.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, profileOf(admin.Uid), u.HomeDir, "fallback should read the profile path")
	assert.Empty(t, u.Gid, "fallback does not resolve a primary group")
}

func TestLookupUserID_FallsBackWhenOSUserFails(t *testing.T) {
	admin := localAdministrator(t)
	failStdLookups(t)

	u, err := LookupUserID(admin.Uid)
	require.NoError(t, err)
	assert.Equal(t, admin.Uid, u.Uid, "fallback should keep the SID")
	assert.Equal(t, admin.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, profileOf(admin.Uid), u.HomeDir, "fallback should read the profile path")
}

// SYSTEM's profile path is stored as %systemroot%\system32\config\systemprofile
// on every Windows install, so it shows whether variables get expanded.
func TestProfileHomeDir_ExpandsVariables(t *testing.T) {
	dir, err := profileHomeDir("S-1-5-18")
	require.NoError(t, err, "SYSTEM always has a profile entry")

	want := filepath.Join(os.Getenv("SystemRoot"), "system32", "config", "systemprofile")
	assert.NotContains(t, dir, "%", "variables in the profile path should be expanded")
	assert.True(t, strings.EqualFold(want, dir), "expected %q, got %q", want, dir)
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
