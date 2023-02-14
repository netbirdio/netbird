//go:build !linux || android
// +build !linux android

package iface

// WireguardModuleIsLoaded check if we can load wireguard mod (linux only)
func WireguardModuleIsLoaded() bool {
	return false
}
