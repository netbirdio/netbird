//go:build windows

package firewall

import "github.com/netbirdio/netbird/client/firewall/uspfilter"

// interfaceAllower returns the Windows netsh-based interface allower.
func interfaceAllower(iface IFaceMapper, _ uint16) uspfilter.InterfaceAllower {
	return uspfilter.NewWindowsInterfaceAllower(iface)
}
