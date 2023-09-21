//go:build !android

package routemanager

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/checkfw"
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

// newFirewall if supported, returns an iptables manager, otherwise returns a nftables manager
func newFirewall(parentCTX context.Context) (firewallManager, error) {
	checkResult := checkfw.Check()
	switch checkResult {
	case checkfw.IPTABLES, checkfw.IPTABLESWITHV6:
		log.Debug("creating an iptables firewall manager for route rules")
		ipv6Supported := checkResult == checkfw.IPTABLESWITHV6
		return newIptablesManager(parentCTX, ipv6Supported)
	case checkfw.NFTABLES:
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
