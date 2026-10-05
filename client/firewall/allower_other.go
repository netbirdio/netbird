//go:build android || (!linux && !windows)

package firewall

import "github.com/netbirdio/netbird/client/firewall/uspfilter"

// interfaceAllower returns no allower: these platforms have no host firewall to
// open for the interface.
func interfaceAllower(IFaceMapper, uint16) uspfilter.InterfaceAllower {
	return nil
}
