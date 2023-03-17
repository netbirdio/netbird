package internal

import (
<<<<<<< HEAD
	log "github.com/sirupsen/logrus"
=======
	"fmt"
>>>>>>> 64bf769 (Add logic layer for the ACL firewall rules management.)

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
)

// buildFirewallManager creates a firewall manager instance for the Linux
func buildFirewallManager(wgIfaceName string) (firewall.Manager, error) {
	fw, err := iptables.Create(wgIfaceName)
	if err != nil {
		// TODO: handle init nftables manager when it will be implemented
		return nil, fmt.Errorf("create iptables manager: %w", err)
	}
	return fw, nil
}
