//go:build !windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"fmt"
	"net"
)

const (
	// MachineInterfaceName is the desired name for the machine tunnel interface.
	MachineInterfaceName = "wg-nb-machine"

	// WireGuardDescription is the adapter description (Windows-specific).
	WireGuardDescription = "WireGuard Tunnel"
)

// InterfaceInfo contains information about a discovered WireGuard interface.
type InterfaceInfo struct {
	Name      string
	GUID      string
	LUID      uint64
	Index     int
	Addresses []net.IPNet
	IsUp      bool
	MTU       int
}

// FindWireGuardInterface is not supported on non-Windows platforms.
func FindWireGuardInterface(guid string) (*InterfaceInfo, error) {
	return nil, fmt.Errorf("FindWireGuardInterface is only supported on Windows")
}

// VerifyInterface is not supported on non-Windows platforms.
func VerifyInterface(info *InterfaceInfo) error {
	return fmt.Errorf("VerifyInterface is only supported on Windows")
}

// HasRouteToNetwork is not supported on non-Windows platforms.
func HasRouteToNetwork(info *InterfaceInfo, network string) (bool, error) {
	return false, fmt.Errorf("HasRouteToNetwork is only supported on Windows")
}
