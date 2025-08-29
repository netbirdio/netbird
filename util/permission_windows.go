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
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(user),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue:             windows.TrusteeValueFromSID(adminGroupSid),
			},
		},
	}

	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(dirPath, windows.SE_FILE_OBJECT, securityFlags, user, group, dacl, nil)
}

func sids() (*windows.SID, *windows.SID, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err := token.Close(); err != nil {
			log.Errorf("failed to close process token: %v", err)
		}
	}()

	tu, err := token.GetTokenUser()
	if err != nil {
		return nil, nil, err
	}

	pg, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return nil, nil, err
	}

	return tu.User.Sid, pg.PrimaryGroup, nil
}
