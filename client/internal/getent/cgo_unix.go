//go:build cgo && !osusergo && !windows

package getent

import "os/user"

// Built with cgo, os/user resolves through libc (getpwnam_r and friends),
// which goes through the host's NSS stack natively. Whatever it fails to
// find, the getent command would not find either, so there is nothing to
// fall back to.

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

// LookupGroupID looks up a group by GID.
func LookupGroupID(gid string) (*user.Group, error) {
	return user.LookupGroupId(gid)
}

// GroupIDs returns the IDs of the groups the user is a member of; libc's
// getgrouplist handles NSS groups natively.
func GroupIDs(u *user.User) ([]string, error) {
	return u.GroupIds()
}
