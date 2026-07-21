//go:build windows

package shell

import "os/user"

// LookupWithGetent on Windows just delegates to os/user.Lookup.
// Windows does not use NSS/getent; its user lookup works without CGO.
func LookupWithGetent(username string) (*user.User, error) {
	return user.Lookup(username)
}

// CurrentUserWithGetent on Windows just delegates to os/user.Current.
func CurrentUserWithGetent() (*user.User, error) {
	return user.Current()
}

// LookupGroupWithGetent on Windows just delegates to os/user.LookupGroup.
func LookupGroupWithGetent(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}

// GetShellFromGetent is a no-op on Windows; shell resolution uses PowerShell detection.
func GetShellFromGetent(_ string) string {
	return ""
}

// GroupIdsWithFallback on Windows just delegates to u.GroupIds().
func GroupIdsWithFallback(u *user.User) ([]string, error) {
	return u.GroupIds()
}
