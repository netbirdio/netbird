//go:build windows

package server

import (
	"os/user"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// usernameForIdentity resolves a Windows caller's SID to its account name.
func usernameForIdentity(id ipcauth.Identity) (string, error) {
	u, err := user.LookupId(id.SID)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
