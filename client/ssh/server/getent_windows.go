//go:build windows

package server

import "os/user"

// lookupWithGetent on Windows just delegates to os/user.Lookup.
// Windows does not use NSS/getent; its user lookup works without CGO.
func lookupWithGetent(username string) (*user.User, error) {
	return user.Lookup(username)
}

// currentUserWithGetent on Windows just delegates to os/user.Current.
func currentUserWithGetent() (*user.User, error) {
	return user.Current()
}

// getShellFromGetent is a no-op on Windows; shell resolution uses PowerShell detection.
func getShellFromGetent(_ string) string {
	return ""
}

// groupIdsWithFallback on Windows just delegates to u.GroupIds().
func groupIdsWithFallback(u *user.User) ([]string, error) {
	return u.GroupIds()
}
