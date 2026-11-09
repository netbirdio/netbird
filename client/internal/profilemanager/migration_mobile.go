//go:build ios || android

package profilemanager

import (
	"os/user"
	"strconv"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// MigrateLegacyProfiles is a no-op on mobile
func (s *ServiceManager) MigrateLegacyProfiles() error {
	return nil
}

// PrincipalForUser turns a resolved account into an owner principal.
func PrincipalForUser(u *user.User) (string, bool) {
	if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
		return ipcauth.UIDPrincipal(uint32(uid)), true
	}
	return "", false
}
