package util

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	securityFlags = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION
)

func EnforcePermission(file string) error {
	dirPath := filepath.Dir(file)

	user, group, err := sids()
	if err != nil {
		return err
	}

	adminGroupSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}

	explicitAccess := []windows.EXPLICIT_ACCESS{
		{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
				windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_USER,
				(windows.TrusteeValueFromSID(user))},
		},
		{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
				windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				windows.TrusteeValueFromSID(adminGroupSid)},
		},
	}

	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(dirPath, windows.SE_FILE_OBJECT, securityFlags, user, group, dacl, nil)
}

func sids() (*windows.SID, *windows.SID, error) {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err := t.Close(); err != nil {
			log.Errorf("failed to close proces token: %v", err)
		}
	}()

	tu, err := t.GetTokenUser()
	if err != nil {
		return nil, nil, err
	}

	pg, err := t.GetTokenPrimaryGroup()
	if err != nil {
		return nil, nil, err
	}

	return tu.User.Sid, pg.PrimaryGroup, nil
}
