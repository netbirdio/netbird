package iface

// WireGuardModuleIsLoaded check if kernel support wireguard
func WireGuardModuleIsLoaded() bool {
	// Despite the fact FreeBSD natively support Wireguard (https://github.com/WireGuard/wireguard-freebsd)
	//  we are currently do not use it, since it is required to add wireguard kernel support to
	//   - https://github.com/netbirdio/netbird/tree/main/sharedsock
	//   - https://github.com/mdlayher/socket
	// TODO: implement kernel space
	return false
}

// tunModuleIsLoaded check if tun module exist, if is not attempt to load it
func tunModuleIsLoaded() bool {
	// Assume tun supported by freebsd kernel by default
	// TODO: implement check for module loaded in kernel or build-it
	return true
}
