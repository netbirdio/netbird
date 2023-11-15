//go:build !android

package routemanager

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
)

const (
	ipv4Forwarding     = "netbird-rt-forwarding"
	ipv4Nat            = "netbird-rt-nat"
	natFormat          = "netbird-nat-%s"
	forwardingFormat   = "netbird-fwd-%s"
	inNatFormat        = "netbird-nat-in-%s"
	inForwardingFormat = "netbird-fwd-in-%s"
)

func genKey(format string, input string) string {
	return fmt.Sprintf(format, input)
}

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall(parentCTX context.Context) (firewallManager, error) {
	checkResult := firewall.Check()
	switch checkResult {
	case firewall.IPTABLES:
		log.Debug("creating an iptables firewall manager for route rules")
		return newIptablesManager(parentCTX)
	case firewall.NFTABLES:
		log.Info("creating an nftables firewall manager for route rules")
		return newNFTablesManager(parentCTX), nil
	}

	return nil, fmt.Errorf("couldn't initialize nftables or iptables clients. Using a dummy firewall manager for route rules")
}

func getInPair(pair routerPair) routerPair {
	return routerPair{
		ID: pair.ID,
		// invert source/destination
		source:      pair.destination,
		destination: pair.source,
		masquerade:  pair.masquerade,
	}
}
