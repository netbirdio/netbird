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

// TOKEN_ELEVATION_TYPE values.
const (
	tokenElevationTypeDefault = 1
	tokenElevationTypeFull    = 2
	tokenElevationTypeLimited = 3
)

// tokenElevationType reads TokenElevationType from a token.
func tokenElevationType(token windows.Token) (uint32, error) {
	var elevationType, returnedLen uint32
	err := windows.GetTokenInformation(token, windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&elevationType)), uint32(unsafe.Sizeof(elevationType)), &returnedLen)
	if err != nil {
		return 0, err
	}
	return elevationType, nil
}

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

// localAccountNames returns the names of the local user accounts.
func localAccountNames(t *testing.T) []string {
	t.Helper()

	var buf *byte
	var entriesRead, totalEntries, resume uint32
	err := windows.NetUserEnum(nil, 0, filterNormalAccount, &buf, maxPreferredLength,
		&entriesRead, &totalEntries, &resume)
	require.NoError(t, err, "enumerate local users")
	t.Cleanup(func() {
		require.NoError(t, windows.NetApiBufferFree(buf), "free NetApi buffer")
	})

	entries := unsafe.Slice((*userInfo0)(unsafe.Pointer(buf)), entriesRead)
	names := make([]string, 0, entriesRead)
	for _, entry := range entries {
		names = append(names, windows.UTF16PtrToString(entry.name))
	}
	return names
}

// localAccountNameByRID returns the name of the local account carrying the
// given RID. Accounts such as Administrator and Guest can be renamed and are
// localized, so tests must not name them literally.
func localAccountNameByRID(t *testing.T, rid uint32) string {
	t.Helper()

	for _, name := range localAccountNames(t) {
		sid, _, _, err := windows.LookupSID("", name)
		if err != nil {
			continue
		}
		if sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY {
			continue
		}
		count := sid.SubAuthorityCount()
		if count < 2 || sid.SubAuthority(0) != 21 {
			continue
		}
		if sid.SubAuthority(uint32(count-1)) == rid {
			return name
		}
	}

	t.Fatalf("no local account with RID %d", rid)
	return ""
}

// wellKnownAccountName resolves a well-known SID to the qualified account name
// the local system uses for it, which is localized.
func wellKnownAccountName(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) string {
	t.Helper()

	sid, err := windows.CreateWellKnownSid(sidType)
	require.NoError(t, err, "create well-known SID")
	name, domain, _, err := sid.LookupAccount("")
	require.NoError(t, err, "resolve %s to an account name", sid)
	if domain == "" {
		return name
	}
	return domain + `\` + name
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

func TestIsWindowsAccountPrivilegedOrUnknown(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{"system", wellKnownAccountName(t, windows.WinLocalSystemSid), true},
		{"local_service", wellKnownAccountName(t, windows.WinLocalServiceSid), true},
		{"network_service", wellKnownAccountName(t, windows.WinNetworkServiceSid), true},
		{"administrators_group", wellKnownAccountName(t, windows.WinBuiltinAdministratorsSid), true},
		// The built-in Administrator (RID 500) and Guest (RID 501) accounts
		// exist on every Windows installation, though they may be disabled.
		{"builtin_administrator", localAccountNameByRID(t, 500), true},
		{"guest", localAccountNameByRID(t, 501), false},
		// Unresolvable accounts fail closed.
		{"nonexistent_user", "netbird-no-such-user", true},
		{"empty_username", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWindowsAccountPrivilegedOrUnknown(tt.username)
			assert.Equal(t, tt.want, result, "account privilege classification for %q", tt.username)
		})
	}
}

func TestIsProcessElevated(t *testing.T) {
	elevated := isProcessElevated()

	// TokenElevationType is a second, independent view of the same token:
	// Full means elevated and Limited means a filtered administrator, while
	// Default covers both a standard user and an administrator with no linked
	// token (UAC off, the built-in Administrator, SYSTEM), so it implies nothing.
	elevationType, err := tokenElevationType(windows.GetCurrentProcessToken())
	require.NoError(t, err, "read token elevation type")

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	// Token(0) makes CheckTokenMembership evaluate the caller's own token. It
	// counts only enabled SIDs, so a filtered administrator reports false here.
	member, err := windows.Token(0).IsMember(adminSid)
	require.NoError(t, err, "check own Administrators membership")

	t.Logf("elevated=%v elevationType=%d memberOfAdministrators=%v", elevated, elevationType, member)

	switch elevationType {
	case tokenElevationTypeFull:
		assert.True(t, elevated, "a token of elevation type Full must report elevated")
	case tokenElevationTypeLimited:
		assert.False(t, elevated, "a filtered administrator token must not report elevated")
	}

	// Administrators enabled in the token means the token wields administrative
	// rights, which is what elevation reports.
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

	checked := 0
	for _, name := range localAccountNames(t) {
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
	// Ineligible accounts are skipped, so without this the test could report
	// success while comparing nothing at all.
	require.Positive(t, checked, "no local account completed an S4U logon, so nothing was compared")
	t.Logf("checked %d local accounts via S4U", checked)
}

// TestLocalGroupsContainSID_Administrator checks the positive case against the
// built-in Administrator, a member of Administrators on every installation.
func TestLocalGroupsContainSID_Administrator(t *testing.T) {
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	administrator := localAccountNameByRID(t, 500)
	member, err := localGroupsContainSID(administrator, adminSid)
	require.NoError(t, err, "enumerate local groups for %s", administrator)
	assert.True(t, member, "%s is a member of the Administrators group", administrator)
}

// TestLocalGroupsContainSID_UnresolvableGroupFailsClosed covers a wanted SID
// that resolves to no group: the error must surface rather than being reported
// as "not a member", so the privilege check treats the account as privileged.
func TestLocalGroupsContainSID_UnresolvableGroupFailsClosed(t *testing.T) {
	unknown := mustParseSID(t, "S-1-5-21-1111111111-2222222222-3333333333-4444")

	_, err := localGroupsContainSID(localAccountNameByRID(t, 500), unknown)
	require.Error(t, err, "must report an error when the wanted group cannot be identified")
}

func TestLocalGroupsContainSID_Guest(t *testing.T) {
	guestsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	require.NoError(t, err, "create Guests SID")
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err, "create Administrators SID")

	guest := localAccountNameByRID(t, 501)

	inGuests, err := localGroupsContainSID(guest, guestsSid)
	require.NoError(t, err, "enumerate local groups for %s", guest)
	assert.True(t, inGuests, "%s is a member of the Guests group", guest)

	inAdmins, err := localGroupsContainSID(guest, adminsSid)
	require.NoError(t, err, "enumerate local groups for %s", guest)
	assert.False(t, inAdmins, "%s is not a member of the Administrators group", guest)
}
