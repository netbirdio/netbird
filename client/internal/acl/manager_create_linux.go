package acl

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
	"github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

// Create creates a firewall manager instance for the Linux
func Create(iface IFaceMapper) (manager *DefaultManager, err error) {
	// on the linux system we try to user nftables or iptables
	// in any case, because we need to allow netbird interface traffic
	// so we use AllowNetbird traffic from these firewall managers
	// for the userspace packet filtering firewall
	var fm firewall.Manager
	if fm, err = nftables.Create(iface); err != nil {
		log.Debugf("failed to create nftables manager: %s", err)
		// fallback to iptables
		if fm, err = iptables.Create(iface); err != nil {
			log.Debugf("failed to create iptables manager: %s", err)
		}
	}
	if fm != nil && err == nil {
		// err shadowing is used here, to ignore this error
		if err := fm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
	}

	if iface.IsUserspaceBind() {
		// use userspace packet filtering firewall
		if fm, err = uspfilter.Create(iface); err != nil {
			log.Debugf("failed to create userspace filtering firewall: %s", err)
			return nil, err
		}
		// to be consistent for any future extensions.
		// ignore this error
		if err := fm.AllowNetbird(); err != nil {
			log.Errorf("failed to allow netbird interface traffic: %v", err)
		}
	}

	if fm == nil || err != nil {
		log.Errorf("failed to create firewall manager: %s", err)
		// no firewall manager found or initalized correctly
		return nil, err
	}

	return newDefaultManager(fm), nil
}
