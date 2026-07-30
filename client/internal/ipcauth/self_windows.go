//go:build windows

package ipcauth

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CurrentProcessIdentity returns this process's identity as the daemon would see
// it if this process connected to the local IPC. It lets a client (the UI)
// decide up front whether a privileged operation can succeed, without a
// round-trip and without duplicating the rules: the answer comes from the same
// Identity.IsPrivileged the daemon applies to the token it reads off the pipe.
func CurrentProcessIdentity() (Identity, error) {
	// A pseudo-token, so it must not be closed.
	token := windows.GetCurrentProcessToken()

	user, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("read token user: %w", err)
	}

	groups, err := tokenGroupSIDs(token)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		SID:      user.User.Sid.String(),
		Groups:   groups,
		Elevated: token.IsElevated(),
	}, nil
}
