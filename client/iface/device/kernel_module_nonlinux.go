//go:build !linux || android

package device

// WireGuardModuleIsLoaded reports whether the kernel WireGuard module is available.
func WireGuardModuleIsLoaded() bool {
	return false
}

// ModuleTunIsLoaded reports whether the tun device is available.
func ModuleTunIsLoaded() bool {
	return true
}
