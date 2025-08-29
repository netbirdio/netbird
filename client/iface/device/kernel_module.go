//go:build (!linux && !freebsd) || android

package device

// WireGuardModuleIsLoaded check if we can load WireGuard mod (linux only)
func WireGuardModuleIsLoaded() bool {
	return false
}
