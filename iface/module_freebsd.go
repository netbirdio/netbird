//go:build freebsd
// +build freebsd

package iface

// WireGuardModuleIsLoaded check if kernel support wireguard
func WireGuardModuleIsLoaded() bool {
    // NOTE: need manually install  https://github.com/WireGuard/wireguard-freebsd
    // pkg install wireguard
    // FIXME: proper implement me
    return true
}

// tunModuleIsLoaded check if tun module exist, if is not attempt to load it
func tunModuleIsLoaded() bool {
    // Assume tun supported by freebsd kernel by default
    return true
}

