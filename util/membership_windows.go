package util

import "golang.zx2c4.com/wireguard/windows/elevate"

// IsAdmin returns true if user has admin privileges
func IsAdmin() bool {
	adminDesktop, err := elevate.IsAdminDesktop()
	if err == nil && adminDesktop {
		return true
	}
	return false
}
