//go:build ios || android

package net

// Init initializes the network environment for mobile platforms.
func Init() {
	// no-op on mobile: routing scope is owned by the VPN extension.
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes.
// Always returns true on mobile since routes cannot be handled dynamically and the VPN extension
// owns the routing scope.
func AdvancedRouting() bool {
	return true
}

// SetVPNInterfaceName is a no-op on mobile.
func SetVPNInterfaceName(string) {
	// no-op on mobile: the VPN extension manages the interface.
}

// GetVPNInterfaceName returns an empty string on mobile.
func GetVPNInterfaceName() string {
	return ""
}
