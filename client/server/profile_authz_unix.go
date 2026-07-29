//go:build !windows

package server

import (
	"strconv"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/shell"
)

// usernameForIdentity resolves a Unix caller's UID to its username via NSS
// (getent), so LDAP/AD users resolve correctly under CGO_ENABLED=0.
func usernameForIdentity(id ipcauth.Identity) (string, error) {
	u, err := shell.GetUserFromGetent(strconv.FormatUint(uint64(id.UID), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
