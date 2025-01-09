//go:build !linux || android

package firewall

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// NewFirewall creates a firewall manager instance
func NewFirewall(iface IFaceMapper, _ *statemanager.Manager, disableServerRoutes bool) (firewall.Manager, error) {
	if !iface.IsUserspaceBind() {
		return nil, fmt.Errorf("not implemented for this OS: %s", runtime.GOOS)
	}

	// use userspace packet filtering firewall
	fm, err := uspfilter.Create(iface, disableServerRoutes)
	if err != nil {
		return nil, err
	}
	err = fm.AllowNetbird()
	if err != nil {
		log.Warnf("failed to allow netbird interface traffic: %v", err)
	}
	return fm, nil
}
