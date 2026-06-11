//go:build windows

package shell

import "os/user"

// lookupWithGetent on Windows just delegates to os/user.Lookup.
// Windows does not use NSS/getent; its user lookup works without CGO.
func LookupWithGetent(username string) (*user.User, error) {
	return user.Lookup(username)
}

// currentUserWithGetent on Windows just delegates to os/user.Current.
func CurrentUserWithGetent() (*user.User, error) {
	return user.Current()
}

// getShellFromGetent is a no-op on Windows; shell resolution uses PowerShell detection.
func GetShellFromGetent(_ string) string {
	return ""
}

// groupIdsWithFallback on Windows just delegates to u.GroupIds().
func GroupIdsWithFallback(u *user.User) ([]string, error) {
	return u.GroupIds()
}
