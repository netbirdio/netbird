//go:build darwin
// +build darwin

package ssh

import (
	"bytes"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
)

func userNameLookup(username string) (*user.User, error) {
	var userObject *user.User
	userObject, err := user.Lookup(username)
	if err != nil && err.Error() == user.UnknownUserError(username).Error() {
		return idUserNameLookup(username)
	} else if err != nil {
		return nil, err
	}

	return userObject, nil
}

func idUserNameLookup(username string) (*user.User, error) {
	cmd := exec.Command("id", "-P", username)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error while retrieving user with id -P command, error: %v", err)
	}
	colon := ":"

	if !bytes.Contains(out, []byte(username+colon)) {
		return nil, fmt.Errorf("unable to find user in returned string")
	}
	// netbird:********:501:20::0:0:netbird:/Users/netbird:/bin/zsh
	parts := strings.SplitN(string(out), colon, 10)
	userObject := &user.User{
		Username: parts[0],
		Uid:      parts[2],
		Gid:      parts[3],
		Name:     parts[7],
		HomeDir:  parts[8],
	}
	return userObject, nil
}
