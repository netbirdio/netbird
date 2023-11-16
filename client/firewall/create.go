//go:build !linux || android

package firewall

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

// NewFirewall creates a firewall manager instance
func NewFirewall(iface IFaceMapper) (manager *DefaultManager, err error) {
	if !iface.IsUserspaceBind() {
		return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
	}

	// use userspace packet filtering firewall
	fm, err := uspfilter.Create(iface)
	if err != nil {
		return nil, err
	}
	err = fm.AllowNetbird()
	if err != nil {
		log.Warnf("failed to allow netbird interface traffic: %v", err)
	}
	return newDefaultManager(fm), nil
}
