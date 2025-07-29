//go:build (!linux && !windows) || android

package net

// Init initializes the network environment (no-op on non-Linux/Windows platforms)
func Init() {
	// No-op on non-Linux/Windows platforms
}

// AdvancedRouting returns false on non-Linux/Windows platforms
func AdvancedRouting() bool {
	return false
}

// SetVPNInterfaceName is a no-op on non-Windows platforms
func SetVPNInterfaceName(name string) {
	// No-op on non-Windows platforms
}

// GetVPNInterfaceName returns empty string on non-Windows platforms
func GetVPNInterfaceName() string {
	return ""
}
