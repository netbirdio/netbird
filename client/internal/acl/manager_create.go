//go:build !linux

package acl

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"

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
		if err := fm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
		return newDefaultManager(fm), nil
	}
	return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
}
