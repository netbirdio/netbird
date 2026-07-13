//go:build cgo && !osusergo && !windows

package server

import "os/user"

// lookupWithGetent with CGO delegates directly to os/user.Lookup.
// When CGO is enabled, os/user uses libc (getpwnam_r) which goes through
// the NSS stack natively. If it fails, the user truly doesn't exist and
// getent would also fail.
func lookupWithGetent(username string) (*user.User, error) {
	return user.Lookup(username)
}

// currentUserWithGetent with CGO delegates directly to os/user.Current.
func currentUserWithGetent() (*user.User, error) {
	return user.Current()
}

// groupIdsWithFallback with CGO delegates directly to user.GroupIds.
// libc's getgrouplist handles NSS groups natively.
func groupIdsWithFallback(u *user.User) ([]string, error) {
	return u.GroupIds()
}
