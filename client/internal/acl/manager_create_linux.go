//go:build !android

package acl

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
	"github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/internal/checkfw"
)

// Create creates a firewall manager instance for the Linux
func Create(iface IFaceMapper) (*DefaultManager, error) {
	// on the linux system we try to user nftables or iptables
	// in any case, because we need to allow netbird interface traffic
	// so we use AllowNetbird traffic from these firewall managers
	// for the userspace packet filtering firewall
	var fm firewall.Manager
	var err error

	checkResult := checkfw.Check()
	switch checkResult {
	case checkfw.IPTABLES, checkfw.IPTABLESWITHV6:
		log.Debug("creating an iptables firewall manager for access control")
		ipv6Supported := checkResult == checkfw.IPTABLESWITHV6
		if fm, err = iptables.Create(iface, ipv6Supported); err != nil {
			log.Infof("failed to create iptables manager for access control: %s", err)
		}
	case checkfw.NFTABLES:
		log.Debug("creating an nftables firewall manager for access control")
		if fm, err = nftables.Create(iface); err != nil {
			log.Debugf("failed to create nftables manager for access control: %s", err)
		}
	}

	var resetHookForUserspace func() error
	if fm != nil && err == nil {
		// err shadowing is used here, to ignore this error
		if err := fm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
		resetHookForUserspace = fm.Reset
	}

	if iface.IsUserspaceBind() {
		// use userspace packet filtering firewall
		usfm, err := uspfilter.Create(iface)
		if err != nil {
			log.Debugf("failed to create userspace filtering firewall: %s", err)
			return nil, err
		}

		// set kernel space firewall Reset as hook for userspace firewall
		// manager Reset method, to clean up
		if resetHookForUserspace != nil {
			usfm.SetResetHook(resetHookForUserspace)
		}

		// to be consistent for any future extensions.
		// ignore this error
		if err := usfm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
		fm = usfm
	}

	if fm == nil || err != nil {
		log.Errorf("failed to create firewall manager: %s", err)
		// no firewall manager found or initialized correctly
		return nil, err
	}

	return newDefaultManager(fm), nil
}
