//go:build !android

package routemanager

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	ipv6Forwarding     = "netbird-rt-ipv6-forwarding"
	ipv4Forwarding     = "netbird-rt-ipv4-forwarding"
	ipv6Nat            = "netbird-rt-ipv6-nat"
	ipv4Nat            = "netbird-rt-ipv4-nat"
	natFormat          = "netbird-nat-%s"
	forwardingFormat   = "netbird-fwd-%s"
	inNatFormat        = "netbird-nat-in-%s"
	inForwardingFormat = "netbird-fwd-in-%s"
	ipv6               = "ipv6"
	ipv4               = "ipv4"
)

func genKey(format string, input string) string {
	return fmt.Sprintf(format, input)
}

// NewFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func NewFirewall(parentCTX context.Context) (firewallManager, error) {
	manager, err := newNFTablesManager(parentCTX)
	if err == nil {
		log.Debugf("nftables firewall manager will be used")
		return manager, nil
	}
	fMgr, err := newIptablesManager(parentCTX)
	if err != nil {
		log.Debugf("failed to initialize iptables for root mgr: %s", err)
		return nil, err
	}
	log.Debugf("iptables firewall manager will be used")
	return fMgr, nil
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
