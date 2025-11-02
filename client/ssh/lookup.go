//go:build !darwin

package ssh

import "os/user"

func userNameLookup(username string) (*user.User, error) {
	if username == "" || (username == "root" && !isRoot()) {
		return user.Current()
	}

	return user.Lookup(username)
}
