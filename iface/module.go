//go:build !linux
// +build !linux

package iface

// WireguardModuleIsLoaded check if we can load wireguard mod (linux only)
func WireguardModuleIsLoaded() bool {
	return false
}
