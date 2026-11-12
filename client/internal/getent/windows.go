//go:build windows

package getent

import (
	"errors"
	"fmt"
	"os/user"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows does not use NSS or getent. os/user resolves accounts there without
// cgo, but it also resolves the account's domain on its own to derive a primary
// group. On a Microsoft Entra ID joined machine that domain is the tenant name,
// which LSA cannot map, so os/user fails for an account that resolves fine. The
// lookups fall back to plain SID and name mapping, which is all callers need.

// stdLookup and stdLookupID are variables so a test can make os/user fail
// without a machine where it really does.
var (
	stdLookup   = user.Lookup
	stdLookupID = user.LookupId
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

// LookupUser looks up a user by name, falling back to an LSA name lookup if
// os/user fails.
func LookupUser(username string) (*user.User, error) {
	u, err := stdLookup(username)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.Lookup(%q) failed, trying LSA: %v", username, err)

	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		log.Debugf("LSA fallback for %q also failed: %v", username, err)
		return nil, stdErr
	}

	u, err = userFromSID(sid)
	if err != nil {
		log.Debugf("LSA fallback for %q also failed: %v", username, err)
		return nil, stdErr
	}
	return u, nil
}

// LookupUserID looks up a user by SID, falling back to an LSA SID lookup if
// os/user fails.
func LookupUserID(uid string) (*user.User, error) {
	u, err := stdLookupID(uid)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.LookupId(%q) failed, trying LSA: %v", uid, err)

	sid, err := windows.StringToSid(uid)
	if err != nil {
		return nil, stdErr
	}

	u, err = userFromSID(sid)
	if err != nil {
		log.Debugf("LSA fallback for %s also failed: %v", uid, err)
		return nil, stdErr
	}
	return u, nil
}

// userFromSID builds a user from the SID and name mapping alone. Gid stays
// empty, since the primary group lookup is the step that fails, and nothing on
// Windows reads it.
func userFromSID(sid *windows.SID) (*user.User, error) {
	account, domain, sidType, err := sid.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("look up account: %w", err)
	}
	if sidType != windows.SidTypeUser {
		return nil, fmt.Errorf("SID is not a user account, type %d", sidType)
	}

	uid := sid.String()
	username := account
	if domain != "" {
		username = domain + `\` + account
	}

	home, err := profileHomeDir(uid)
	if err != nil {
		log.Debugf("no profile path for %s, leaving its home directory empty: %v", uid, err)
	}

	return &user.User{
		Uid:      uid,
		Username: username,
		Name:     account,
		HomeDir:  home,
	}, nil
}

// profileHomeDir reads the profile path Windows records for an account that
// has signed in at least once.
func profileHomeDir(uid string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey+uid, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := k.Close(); err != nil {
			log.Debugf("close profile list key: %v", err)
		}
	}()

	dir, valType, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valType != registry.EXPAND_SZ {
		return dir, nil
	}
	return registry.ExpandString(dir)
}

// CurrentUser returns the user this process runs as.
func CurrentUser() (*user.User, error) {
	return user.Current()
}

// GroupIDs returns the IDs of the groups the user is a member of.
func GroupIDs(u *user.User) ([]string, error) {
	return u.GroupIds()
}

// UserShell is unanswerable on Windows, which has no login-shell database.
func UserShell(string) (string, error) {
	return "", errors.ErrUnsupported
}
