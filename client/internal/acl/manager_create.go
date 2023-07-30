//go:build !linux

package acl

import (
	"fmt"
	"runtime"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

// Create creates a firewall manager instance
func Create(iface IFaceMapper) (manager *DefaultManager, err error) {
	if iface.IsUserspaceBind() {
		// use userspace packet filtering firewall
		fm, err := uspfilter.Create(iface)
		if err != nil {
			return nil, err
		}
		return newDefaultManager(fm), nil
	}
	return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
}
