//go:build !linux

package server

import "os/user"

// needsSessionContext is always false on platforms without SELinux.
func needsSessionContext(string, []string) bool {
	return false
}

// localGroupNames has nothing to resolve on platforms without SELinux.
func localGroupNames(*user.User) []string {
	return nil
}
