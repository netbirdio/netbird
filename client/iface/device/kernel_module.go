//go:build (!linux && !freebsd) || android

package device

import "github.com/netbirdio/netbird/client/internal/amneziawg"

// WireGuardModuleIsLoaded check if we can load WireGuard mod (linux only)
func WireGuardModuleIsLoaded(conf amneziawg.AmneziaConfig) bool {
	return false
}
