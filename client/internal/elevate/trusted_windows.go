package elevate

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeAccess are the rights that let a trustee replace or rewrite an
// executable, or take it over and then do so.
const writeAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// trustedInstallerSID owns much of what Windows itself installs. x/sys has no
// well-known constant for it.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// unprivilegedTrustees are the well-known groups that contain accounts which
// cannot elevate on their own. Granting any of them write access to the
// executable would mean an account that cannot pass the UAC prompt could still
// decide what runs behind it.
var unprivilegedTrustees = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinWorldSid,             // Everyone
	windows.WinAuthenticatedUserSid, // Authenticated Users
	windows.WinInteractiveSid,       // INTERACTIVE
	windows.WinBuiltinUsersSid,      // BUILTIN\Users
	windows.WinBuiltinGuestsSid,     // BUILTIN\Guests
}

// checkOnlyOwnerWritable reports an error unless path is owned by an account
// that can elevate (or by this user) and grants write access to no group of
// accounts that cannot. Its directory is checked the same way, because being
// able to write the directory is being able to replace the file in it.
func checkOnlyOwnerWritable(path string) error {
	for _, target := range []string{path, filepath.Dir(path)} {
		if err := checkSecurity(target); err != nil {
			return err
		}
	}
	return nil
}

func checkSecurity(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}
	if err := checkOwner(path, owner); err != nil {
		return err
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

	return checkDACL(path, dacl)
}

// checkOwner accepts an owner that can elevate by itself, plus this user: their
// own executable is theirs to write, and code already running as them could
// prompt for anything anyway.
func checkOwner(path string, owner *windows.SID) error {
	self, err := currentUserSID()
	if err != nil {
		return err
	}
	if owner.Equals(self) {
		return nil
	}

	for _, wellKnown := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(wellKnown)
		if err != nil {
			return fmt.Errorf("build well-known SID %d: %w", wellKnown, err)
		}
		if owner.Equals(sid) {
			return nil
		}
	}

	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return fmt.Errorf("parse TrustedInstaller SID: %w", err)
	}
	if owner.Equals(installer) {
		return nil
	}

	return fmt.Errorf("%s is owned by %s, which is neither this user nor an account that can elevate", path, owner)
}

func checkDACL(path string, dacl *windows.ACL) error {
	untrusted := make([]*windows.SID, 0, len(unprivilegedTrustees))
	for _, wellKnown := range unprivilegedTrustees {
		sid, err := windows.CreateWellKnownSid(wellKnown)
		if err != nil {
			return fmt.Errorf("build well-known SID %d: %w", wellKnown, err)
		}
		untrusted = append(untrusted, sid)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Mask&writeAccess == 0 {
			continue
		}

		//nolint:gosec // SidStart is the first uint32 of the variable-length SID that follows the ACE header.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, bad := range untrusted {
			if sid.Equals(bad) {
				return fmt.Errorf("%s grants write access to %s", path, bad)
			}
		}
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read this process's user: %w", err)
	}
	return user.User.Sid, nil
}
