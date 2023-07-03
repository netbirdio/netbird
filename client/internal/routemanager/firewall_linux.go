//go:build !android

package routemanager

import (
	"context"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
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
func NewFirewall(parentCTX context.Context) firewallManager {
	ctx, cancel := context.WithCancel(parentCTX)

	if isIptablesSupported() {
		log.Debugf("iptables is supported")
		ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if !isIptablesClientAvailable(ipv4Client) {
			log.Infof("iptables is missing for ipv4")
			ipv4Client = nil
		}
		ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if !isIptablesClientAvailable(ipv6Client) {
			log.Infof("iptables is missing for ipv6")
			ipv6Client = nil
		}

		return &iptablesManager{
			ctx:        ctx,
			stop:       cancel,
			ipv4Client: ipv4Client,
			ipv6Client: ipv6Client,
			rules:      make(map[string]map[string][]string),
		}
	}

	log.Debugf("iptables is not supported, using nftables")

	manager := &nftablesManager{
		ctx:    ctx,
		stop:   cancel,
		conn:   &nftables.Conn{},
		chains: make(map[string]map[string]*nftables.Chain),
		rules:  make(map[string]*nftables.Rule),
	}

	return manager
}

func isIptablesClientAvailable(client *iptables.IPTables) bool {
	_, err := client.ListChains("filter")
	return err == nil
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
