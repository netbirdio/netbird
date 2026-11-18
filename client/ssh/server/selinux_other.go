//go:build !linux

package server

import "os/user"

// needsSessionContext is always false on platforms without SELinux.
func needsSessionContext(string, []string, error) bool {
	return false
}

// checkLoginContext never refuses a session on platforms without SELinux.
func checkLoginContext(string, []string, error) error {
	return nil
}

// localGroupNames has nothing to resolve on platforms without SELinux.
func localGroupNames(*user.User) ([]string, error) {
	return nil, nil
}
