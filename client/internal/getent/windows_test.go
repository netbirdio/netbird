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
	"golang.org/x/sys/windows/registry"
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

// stubProfileDir makes the profile lookup return dir and err, so the tests do
// not depend on whether the account has signed in on the test machine.
func stubProfileDir(t *testing.T, dir string, err error) {
	t.Helper()
	orig := readProfileDir
	readProfileDir = func(string) (string, error) { return dir, err }
	t.Cleanup(func() { readProfileDir = orig })
}

func TestLookupUser_FallsBackWhenOSUserFails(t *testing.T) {
	admin := localAdministrator(t)
	failStdLookups(t)
	stubProfileDir(t, `C:\Users\stub`, nil)

	u, err := LookupUser(admin.Username)
	require.NoError(t, err)
	assert.Equal(t, admin.Uid, u.Uid, "fallback should resolve the same SID")
	assert.Equal(t, admin.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, `C:\Users\stub`, u.HomeDir, "fallback should report the profile path")
	assert.Empty(t, u.Gid, "fallback does not resolve a primary group")
}

func TestLookupUserID_FallsBackWhenOSUserFails(t *testing.T) {
	admin := localAdministrator(t)
	failStdLookups(t)
	stubProfileDir(t, `C:\Users\stub`, nil)

	u, err := LookupUserID(admin.Uid)
	require.NoError(t, err)
	assert.Equal(t, admin.Uid, u.Uid, "fallback should keep the SID")
	assert.Equal(t, admin.Username, u.Username, "fallback should report DOMAIN\\account")
	assert.Equal(t, `C:\Users\stub`, u.HomeDir, "fallback should report the profile path")
}

// A profile path that cannot be read must not fail the lookup, only leave the
// home directory empty. Covers both an account that never signed in and a read
// that fails for another reason.
func TestLookupUserID_FallbackWithoutProfilePath(t *testing.T) {
	admin := localAdministrator(t)
	failStdLookups(t)

	for name, err := range map[string]error{
		"no profile entry": registry.ErrNotExist,
		"unreadable entry": errors.New("access is denied"),
	} {
		t.Run(name, func(t *testing.T) {
			stubProfileDir(t, "", err)

			u, lookupErr := LookupUserID(admin.Uid)
			require.NoError(t, lookupErr, "a missing profile path must not fail the lookup")
			assert.Equal(t, admin.Uid, u.Uid, "the account still resolves")
			assert.Empty(t, u.HomeDir, "the home directory is left empty")
		})
	}
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
