package acl

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
	"github.com/netbirdio/netbird/client/firewall/nftables"
)

// Create creates a firewall manager instance for the Linux
func Create(wgIfaceName string) (manager *DefaultManager, err error) {
	var fm firewall.Manager
	if fm, err = iptables.Create(wgIfaceName); err != nil {
		log.Debugf("failed to create iptables manager: %s", err)
		// fallback to nftables
		if fm, err = nftables.Create(wgIfaceName); err != nil {
			log.Errorf("failed to create nftables manager: %s", err)
			return nil, err
		}
	}

	return &DefaultManager{
		manager: fm,
		rules:   make(map[string]firewall.Rule),
	}, nil
}
