//go:build ios || android

package net

// Init initializes the network environment for mobile platforms.
func Init() {
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes.
// Always returns true on mobile since routes cannot be handled dynamically and the VPN extension
// owns the routing scope.
func AdvancedRouting() bool {
	return true
}

// SetVPNInterfaceName is a no-op on mobile.
func SetVPNInterfaceName(string) {
}

// GetVPNInterfaceName returns an empty string on mobile.
func GetVPNInterfaceName() string {
	return ""
}
