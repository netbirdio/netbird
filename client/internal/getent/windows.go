//go:build windows

package getent

import (
	"errors"
	"os/user"
)

// Windows does not use NSS or getent; os/user resolves accounts there
// without cgo, so everything delegates to it.

// LookupUser looks up a user by name.
func LookupUser(username string) (*user.User, error) {
	return user.Lookup(username)
}

// LookupUserID looks up a user by UID.
func LookupUserID(uid string) (*user.User, error) {
	return user.LookupId(uid)
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
