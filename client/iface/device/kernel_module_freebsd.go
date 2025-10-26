package device

import "github.com/netbirdio/netbird/client/internal/amneziawg"

// WireGuardModuleIsLoaded check if kernel support wireguard
func WireGuardModuleIsLoaded(conf amneziawg.AmneziaConfig) bool {
	// Despite the fact FreeBSD natively support Wireguard (https://github.com/WireGuard/wireguard-freebsd)
	//  we are currently do not use it, since it is required to add wireguard kernel support to
	//   - https://github.com/netbirdio/netbird/tree/main/sharedsock
	//   - https://github.com/mdlayher/socket
	// TODO: implement kernel space
	return false
}

// ModuleTunIsLoaded check if tun module exist, if is not attempt to load it
func ModuleTunIsLoaded() bool {
	// Assume tun supported by freebsd kernel by default
	// TODO: implement check for module loaded in kernel or build-it
	return true
}
