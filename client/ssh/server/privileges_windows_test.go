//go:build windows

package server

import (
	"os/user"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// filterNormalAccount limits NetUserEnum to normal user accounts.
const filterNormalAccount = 0x2

// userInfo0 mirrors USER_INFO_0.
type userInfo0 struct {
	name *uint16
}

func mustParseSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	require.NoError(t, err, "parse SID %s", s)
	return sid
}

func TestIsBuiltinAdministratorSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want bool
	}{
		{"machine_administrator", "S-1-5-21-1111111111-2222222222-3333333333-500", true},
		{"domain_administrator", "S-1-5-21-3390233681-4087452608-412898826-500", true},
		{"regular_user", "S-1-5-21-1111111111-2222222222-3333333333-1001", false},
		{"guest_account", "S-1-5-21-1111111111-2222222222-3333333333-501", false},
		{"domain_admins_group", "S-1-5-21-1111111111-2222222222-3333333333-512", false},
		{"system", "S-1-5-18", false},
		{"administrators_group", "S-1-5-32-544", false},
		{"non_nt_authority", "S-1-1-0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBuiltinAdministratorSID(mustParseSID(t, tt.sid))
			assert.Equal(t, tt.want, result, "RID 500 detection for %s", tt.sid)
		})
	}
}

func TestIsPrivilegedUserSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want bool
	}{
		{"local_system", "S-1-5-18", true},
		{"local_service", "S-1-5-19", true},
		{"network_service", "S-1-5-20", true},
		{"administrators_group", "S-1-5-32-544", true},
		{"builtin_administrator", "S-1-5-21-1111111111-2222222222-3333333333-500", true},
		{"regular_user", "S-1-5-21-1111111111-2222222222-3333333333-1001", false},
		{"users_group", "S-1-5-32-545", false},
		{"everyone", "S-1-1-0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrivilegedUserSID(mustParseSID(t, tt.sid))
			assert.Equal(t, tt.want, result, "SID privilege classification for %s", tt.sid)
		})
	}
}

func TestIsWindowsAccountPrivileged(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{"system", "NT AUTHORITY\\SYSTEM", true},
		{"local_service", "NT AUTHORITY\\LOCAL SERVICE", true},
		{"network_service", "NT AUTHORITY\\NETWORK SERVICE", true},
		{"administrators_group_name", "BUILTIN\\Administrators", true},
		// The built-in Administrator and Guest accounts exist on every
		// Windows installation, though they may be disabled.
		{"builtin_administrator", "Administrator", true},
		{"guest", "Guest", false},
		// Unresolvable accounts fail closed.
		{"nonexistent_user", "netbird-no-such-user", true},
		{"empty_username", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWindowsAccountPrivileged(tt.username)
			assert.Equal(t, tt.want, result, "account privilege classification for %q", tt.username)
		})
	}
}

func TestIsProcessElevated(t *testing.T) {
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	// Token(0) makes CheckTokenMembership evaluate the caller's own token.
	member, err := windows.Token(0).IsMember(adminSid)
	require.NoError(t, err, "check own Administrators membership")

	elevated := isProcessElevated()
	t.Logf("member of Administrators: %v, token elevated: %v", member, elevated)

	// An enabled Administrators SID in the token implies an elevated token.
	// CI runs this test as SYSTEM, which satisfies both.
	if member {
		assert.True(t, elevated, "token with enabled Administrators membership must report elevated")
	}
}

// TestS4UMembershipAgreesWithLocalGroups exercises the S4U token path used
// for domain accounts. S4U logons need the TCB privilege, so the test runs
// only as SYSTEM (which is how CI executes the suite). For local accounts the
// token's Administrators membership must agree with the SAM enumeration.
func TestS4UMembershipAgreesWithLocalGroups(t *testing.T) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err, "create SYSTEM SID")
	current, err := user.Current()
	require.NoError(t, err, "get current user")
	if current.Uid != system.String() {
		t.Skipf("S4U logon requires SYSTEM (running as %s)", current.Username)
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	var buf *byte
	var entriesRead, totalEntries uint32
	var resume uint32
	err = windows.NetUserEnum(nil, 0, filterNormalAccount, &buf, maxPreferredLength,
		&entriesRead, &totalEntries, &resume)
	require.NoError(t, err, "enumerate local users")
	defer func() {
		require.NoError(t, windows.NetApiBufferFree(buf), "free NetApi buffer")
	}()

	names := unsafe.Slice((*userInfo0)(unsafe.Pointer(buf)), entriesRead)
	checked := 0
	for _, entry := range names {
		name := windows.UTF16PtrToString(entry.name)

		viaToken, err := s4uTokenIsMember(name, ".", adminSid)
		if err != nil {
			// Disabled or logon-restricted accounts cannot get an S4U logon.
			t.Logf("skipping %s: %v", name, err)
			continue
		}
		viaSAM, err := localGroupsContainSID(name, adminSid)
		require.NoError(t, err, "enumerate local groups for %s", name)

		assert.Equal(t, viaSAM, viaToken, "S4U token and SAM enumeration must agree on Administrators membership for %s", name)
		checked++
	}
	t.Logf("checked %d local accounts via S4U", checked)
}

// TestLocalGroupsContainSID_Administrator checks the positive case against an
// account that is a member of Administrators on every Windows installation.
func TestLocalGroupsContainSID_Administrator(t *testing.T) {
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	member, err := localGroupsContainSID("Administrator", adminSid)
	require.NoError(t, err, "enumerate local groups for Administrator")
	assert.True(t, member, "the built-in Administrator is a member of Administrators")
}

// TestLocalGroupsContainSID_UnresolvableGroupFailsClosed covers a wanted SID
// that resolves to no group: the error must surface rather than being reported
// as "not a member", so the privilege check treats the account as privileged.
func TestLocalGroupsContainSID_UnresolvableGroupFailsClosed(t *testing.T) {
	unknown := mustParseSID(t, "S-1-5-21-1111111111-2222222222-3333333333-4444")

	_, err := localGroupsContainSID("Administrator", unknown)
	require.Error(t, err, "must report an error when the wanted group cannot be identified")
}

func TestLocalGroupsContainSID_Guest(t *testing.T) {
	guestsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	require.NoError(t, err, "create Guests SID")
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	inGuests, err := localGroupsContainSID("Guest", guestsSid)
	require.NoError(t, err, "enumerate local groups for Guest")
	assert.True(t, inGuests, "Guest should be a member of BUILTIN\\Guests")

	inAdmins, err := localGroupsContainSID("Guest", adminsSid)
	require.NoError(t, err, "enumerate local groups for Guest")
	assert.False(t, inAdmins, "Guest should not be a member of BUILTIN\\Administrators")
}
