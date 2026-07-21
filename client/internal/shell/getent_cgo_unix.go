//go:build cgo && !osusergo && !windows

package shell

import "os/user"

// LookupWithGetent with CGO delegates directly to os/user.Lookup.
// When CGO is enabled, os/user uses libc (getpwnam_r) which goes through
// the NSS stack natively. If it fails, the user truly doesn't exist and
// getent would also fail.
func LookupWithGetent(username string) (*user.User, error) {
	return user.Lookup(username)
}

// CurrentUserWithGetent with CGO delegates directly to os/user.Current.
func CurrentUserWithGetent() (*user.User, error) {
	return user.Current()
}

// LookupGroupWithGetent returns the resolved group from either a gid or groupname.
func LookupGroupWithGetent(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}

// GroupIdsWithFallback with CGO delegates directly to user.GroupIds.
// libc's getgrouplist handles NSS groups natively.
func GroupIdsWithFallback(u *user.User) ([]string, error) {
	return u.GroupIds()
}
