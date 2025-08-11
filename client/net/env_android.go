//go:build android

package net

// Init initializes the network environment for Android
func Init() {
	// No initialization needed on Android
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes.
// Always returns true on Android since we cannot handle routes dynamically.
func AdvancedRouting() bool {
	return true
}
