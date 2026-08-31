package elevate

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// fileDeleteChild is FILE_DELETE_CHILD, which x/sys does not define: the
	// right to delete an entry of a directory without holding DELETE on it.
	fileDeleteChild = 0x00000040

	// accessAllowedCallbackACEType is an allow ACE with a condition appended to
	// the ACCESS_ALLOWED_ACE layout, so its trustee is still at SidStart.
	accessAllowedCallbackACEType = 0x9

	// The allow ACE types that carry object GUIDs ahead of the trustee, so the
	// SID is not at SidStart. They occur on directory-service objects rather
	// than files, and are refused rather than skipped: see aceTrustee.
	accessAllowedObjectACEType         = 0x5
	accessAllowedCallbackObjectACEType = 0xB
)

// fileWriteAccess are the rights that let a trustee rewrite or replace a file,
// or take it over and then do so.
const fileWriteAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// dirWriteAccess are the rights over a directory that let a trustee replace an
// entry somebody else owns. Creating a new entry is not one of them, which is
// what the Unix sticky bit says in one bit: the root of every volume grants
// BUILTIN\Users the right to add directories under it, and that reaches nothing
// already there.
const dirWriteAccess = fileDeleteChild | windows.DELETE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// trustedInstallerSID owns much of what Windows itself installs. x/sys has no
// well-known constant for it.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// checkOnlyOwnerWritable reports an error unless path, and every directory
// leading to it, is owned by an account that can elevate (or by this user) and
// grants write access to nobody else. A writable directory is as good as a
// writable file, since an entry in it can be replaced, so the whole chain is
// checked.
func checkOnlyOwnerWritable(path string) error {
	owners, err := trustedOwners()
	if err != nil {
		return err
	}
	writers, err := trustedWriters(owners)
	if err != nil {
		return err
	}

	writeAccess := windows.ACCESS_MASK(fileWriteAccess)
	for target := path; ; target = filepath.Dir(target) {
		if err := checkSecurity(target, writeAccess, owners, writers); err != nil {
			return err
		}
		if parent := filepath.Dir(target); parent == target {
			return nil
		}
		writeAccess = dirWriteAccess
	}
}

// trustedOwners are the accounts we accept as the owner of the executable and of
// the directories above it: the ones that can already answer the UAC prompt,
// plus this user, whose own executable is theirs to write. Code running as the
// user could prompt them for anything anyway; what matters is that no *other*
// unprivileged account can reach it.
func trustedOwners() ([]*windows.SID, error) {
	self, err := currentUserSID()
	if err != nil {
		return nil, err
	}

	owners := []*windows.SID{self}
	for _, wellKnown := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(wellKnown)
		if err != nil {
			return nil, fmt.Errorf("build well-known SID %d: %w", wellKnown, err)
		}
		owners = append(owners, sid)
	}

	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return nil, fmt.Errorf("parse TrustedInstaller SID: %w", err)
	}
	return append(owners, installer), nil
}

// trustedWriters are the trustees whose write access does not widen who could
// decide what runs behind the prompt. The owners, and CREATOR OWNER, which
// resolves to the object's owner and is therefore already vetted.
func trustedWriters(owners []*windows.SID) ([]*windows.SID, error) {
	creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		return nil, fmt.Errorf("build the CREATOR OWNER SID: %w", err)
	}
	return append(slices.Clone(owners), creatorOwner), nil
}

func checkSecurity(path string, writeAccess windows.ACCESS_MASK, owners, writers []*windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}
	if !containsSID(owners, owner) {
		return fmt.Errorf("%s is owned by %s, which is neither this user nor an account that can elevate", path, owner)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	// A NULL DACL grants everyone everything; only an absent security
	// descriptor would have got us here without one, and neither is trustworthy.
	if dacl == nil {
		return fmt.Errorf("%s has no DACL, so it grants write access to everyone", path)
	}

	return checkDACL(path, dacl, writeAccess, writers)
}

// checkDACL refuses an ACL that grants write access to a trustee outside
// writers.
//
// An allowlist, because the trustees that must not have it cannot be listed: an
// ACE naming an ordinary user account hands that account the same power as one
// naming Everyone, and only the accounts that may hold it are knowable.
func checkDACL(path string, dacl *windows.ACL, writeAccess windows.ACCESS_MASK, writers []*windows.SID) error {
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		// An inherit-only ACE says what children of this object get, not what
		// this object grants.
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Mask&writeAccess == 0 {
			continue
		}
		// Only an allow ACE grants anything; a deny ACE narrows what one gave.
		if !isAllowACE(ace.Header.AceType) {
			continue
		}

		trustee, err := aceTrustee(ace)
		if err != nil {
			return fmt.Errorf("read the trustee of ACE %d of %s: %w", i, path, err)
		}
		if !containsSID(writers, trustee) {
			return fmt.Errorf("%s grants write access to %s", path, trustee)
		}
	}
	return nil
}

// isAllowACE reports whether an ACE type grants rights, rather than denying,
// auditing or labelling them.
func isAllowACE(aceType uint8) bool {
	switch aceType {
	case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType,
		accessAllowedObjectACEType, accessAllowedCallbackObjectACEType:
		return true
	default:
		return false
	}
}

// aceTrustee returns who an allow ACE grants its rights to. An ACE whose trustee
// cannot be located is an error rather than something to skip past: being unable
// to read who is being given write access is a refusal.
func aceTrustee(ace *windows.ACCESS_ALLOWED_ACE) (*windows.SID, error) {
	switch ace.Header.AceType {
	case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
		//nolint:gosec // SidStart is the first uint32 of the variable-length SID that follows the ACE header.
		return (*windows.SID)(unsafe.Pointer(&ace.SidStart)), nil
	default:
		return nil, errors.New("an object-type allow ACE does not carry its trustee where we can read it")
	}
}

func containsSID(sids []*windows.SID, sid *windows.SID) bool {
	return slices.ContainsFunc(sids, sid.Equals)
}

func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read this process's user: %w", err)
	}
	return user.User.Sid, nil
}
