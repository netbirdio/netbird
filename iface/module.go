//go:build !linux || android
// +build !linux android

package iface

// WireGuardModuleIsLoaded check if we can load WireGuard mod (linux only)
func WireGuardModuleIsLoaded() bool {
	return false
}
