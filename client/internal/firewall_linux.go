package internal

import (
	"fmt"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/iptables"
)

func buildFirewallManager() (fw firewall.Manager, err error) {
	fw, err = iptables.Create()
	if err != nil {
		// TODO: handle init nftables manager when it will be implemented
		return nil, fmt.Errorf("create iptables manager: %w", err)
	}
	return fw, nil
}
