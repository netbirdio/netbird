package internal

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
)

// buildFirewallManager creates a firewall manager instance for the Linux
func buildFirewallManager(wgIfaceName string) (firewall.Manager, error) {
	fw, err := iptables.Create(wgIfaceName)
	if err != nil {
		log.Debugf("failed to create iptables manager: %s", err)
		return nil, err
	}
	return fw, nil
}
