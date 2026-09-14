//go:build windows

package server

import (
	"fmt"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	netapi32                  = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserGetLocalGroups = netapi32.NewProc("NetUserGetLocalGroups")
)

const (
	// lgIncludeIndirect makes NetUserGetLocalGroups also return local groups
	// the user belongs to through a global group.
	lgIncludeIndirect  = 0x1
	maxPreferredLength = 0xFFFFFFFF
)

// localGroupUsersInfo0 mirrors LOCALGROUP_USERS_INFO_0.
type localGroupUsersInfo0 struct {
	name *uint16
}

// isProcessElevated reports whether the current process token is elevated
// (TokenElevation): true for elevated administrators, the built-in
// Administrator, administrators with UAC disabled, and SYSTEM; false for
// standard users and administrators running with a UAC-filtered token.
func isProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// isWindowsAccountPrivilegedOrUnknown reports whether the account is privileged
// on this machine: a well-known service account, a built-in Administrator
// (RID 500), or a member of the local Administrators group, directly or through
// nested groups.
//
// An account whose privilege cannot be determined counts as privileged, which
// is why the name says "or unknown". That is fail-closed for a caller that
// refuses privileged accounts, and fail-open for a caller that grants something
// to them, so only the former may use this.
func isWindowsAccountPrivilegedOrUnknown(username string) bool {
	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		log.Warnf("privilege check: SID lookup for %q failed, treating as privileged: %v", username, err)
		return true
	}

	if isPrivilegedUserSID(sid) {
		return true
	}

	member, err := isLocalAdminsMember(username)
	if err != nil {
		log.Warnf("privilege check: cannot determine Administrators membership for %q, treating as privileged: %v", username, err)
		return true
	}
	return member
}

// isPrivilegedUserSID reports whether the SID itself identifies a privileged
// principal, without consulting group membership.
func isPrivilegedUserSID(sid *windows.SID) bool {
	wellKnown := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinLocalServiceSid,
		windows.WinNetworkServiceSid,
		windows.WinBuiltinAdministratorsSid,
	}
	for _, sidType := range wellKnown {
		if sid.IsWellKnown(sidType) {
			return true
		}
	}
	return isBuiltinAdministratorSID(sid)
}

// isBuiltinAdministratorSID reports whether the SID is a machine or domain
// built-in Administrator account (S-1-5-21-...-500). RID 500 is reserved for
// that account; it can be renamed but cannot be removed from the
// Administrators group.
func isBuiltinAdministratorSID(sid *windows.SID) bool {
	if sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY {
		return false
	}
	count := sid.SubAuthorityCount()
	if count < 2 || sid.SubAuthority(0) != 21 {
		return false
	}
	return sid.SubAuthority(uint32(count-1)) == 500
}

// isLocalAdminsMember reports whether the account is a member of the local
// Administrators group.
//
// Local accounts are checked against the local SAM, which is authoritative for
// them and, unlike a token, cannot under-report: UAC filters the tokens of
// local administrators, and a filtered token carries Administrators as
// deny-only, which a membership check on the token would read as "not a
// member". Domain accounts are exempt from that filtering, so for them an S4U
// token is preferred because its group list is LSA's transitive expansion and
// therefore covers nested and universal groups plus the machine's own local
// groups. NetUserGetLocalGroups expands only one global-group hop but needs no
// logon, so it serves as the fallback when no token can be obtained.
func isLocalAdminsMember(username string) (bool, error) {
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("create Administrators SID: %w", err)
	}

	account, domain := parseUsername(username)
	if NewPrivilegeDropper().isLocalUser(domain) {
		return localGroupsContainSID(account, adminSid)
	}

	member, s4uErr := s4uTokenIsMember(account, domain, adminSid)
	if s4uErr == nil {
		return member, nil
	}
	log.Debugf("privilege check: S4U membership check for %q failed, falling back to local group enumeration: %v", username, s4uErr)

	member, err = localGroupsContainSID(buildUserCpn(account, domain), adminSid)
	if err != nil {
		return false, fmt.Errorf("S4U check: %w; local group enumeration: %w", s4uErr, err)
	}
	return member, nil
}

// s4uTokenIsMember obtains an S4U token for the account and checks whether the
// given SID is enabled in it.
func s4uTokenIsMember(account, domain string, sid *windows.SID) (bool, error) {
	token, err := generateS4UUserToken(log.NewEntry(log.StandardLogger()), account, domain)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := windows.CloseHandle(token); err != nil {
			log.Debugf("close S4U token: %v", err)
		}
	}()
	return windows.Token(token).IsMember(sid)
}

// localGroupsContainSID reports whether the wanted group is among the local
// groups the account belongs to, directly or through a global group.
//
// The wanted SID is resolved to its group name once and compared against the
// enumerated names. Well-known SIDs resolve from a static table, so that lookup
// needs no domain controller, and it keeps the comparison correct for a renamed
// or localized group because both sides then carry the new name. Resolving each
// enumerated name back to a SID instead would add a lookup per group that can
// block until it times out while a domain controller is unreachable, and cannot
// change the outcome: the names enumerated here are local groups of this
// machine, whose names are unique, so a name match identifies the group.
//
// A failure to resolve the wanted SID is returned rather than reported as
// "not a member", so a privilege check built on this fails closed.
func localGroupsContainSID(username string, want *windows.SID) (bool, error) {
	wantName, _, _, err := want.LookupAccount("")
	if err != nil {
		return false, fmt.Errorf("resolve group SID %s to a name: %w", want, err)
	}

	groups, err := netUserGetLocalGroups(username)
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		if strings.EqualFold(group, wantName) {
			return true, nil
		}
	}
	return false, nil
}

// netUserGetLocalGroups returns the names of the local groups the account is a
// member of, including indirect membership through global groups.
func netUserGetLocalGroups(username string) ([]string, error) {
	name16, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return nil, fmt.Errorf("convert username: %w", err)
	}

	var buf *byte
	var entriesRead, totalEntries uint32
	status, _, _ := procNetUserGetLocalGroups.Call(
		0, // local server
		uintptr(unsafe.Pointer(name16)),
		0, // level 0: LOCALGROUP_USERS_INFO_0
		lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
	)
	if status != 0 {
		return nil, fmt.Errorf("NetUserGetLocalGroups for %q: status %d", username, status)
	}
	if buf == nil {
		return nil, nil
	}
	defer func() {
		if err := windows.NetApiBufferFree(buf); err != nil {
			log.Debugf("free NetApi buffer: %v", err)
		}
	}()

	// MAX_PREFERRED_LENGTH makes the API allocate as much as it needs, so a
	// short read is not expected. Report it rather than silently returning a
	// subset of the account's groups.
	if entriesRead != totalEntries {
		return nil, fmt.Errorf("NetUserGetLocalGroups for %q returned %d of %d groups", username, entriesRead, totalEntries)
	}

	entries := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buf)), entriesRead)
	groups := make([]string, 0, entriesRead)
	for _, entry := range entries {
		groups = append(groups, windows.UTF16PtrToString(entry.name))
	}
	return groups, nil
}
