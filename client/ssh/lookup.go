//go:build !darwin
// +build !darwin

package ssh

import "os/user"

func userNameLookup(username string) (*user.User, error) {
	return user.Lookup(username)
}
