package internal

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
	"github.com/netbirdio/netbird/client/firewall/nftables"
)

// buildFirewallManager creates a firewall manager instance for the Linux
func buildFirewallManager(wgIfaceName string) (fm firewall.Manager, err error) {
	if fm, err = iptables.Create(wgIfaceName); err != nil {
		log.Debugf("failed to create iptables manager: %s", err)
		// fallback to nftables
		if fm, err = nftables.Create(wgIfaceName); err != nil {
			log.Errorf("failed to create nftables manager: %s", err)
			return nil, err
		}
	}
	return fm, nil
}
