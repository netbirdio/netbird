package routemanager

import (
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
)
import "github.com/google/nftables"

const (
	Ipv6Forwarding   = "netbird-rt-ipv6-forwarding"
	Ipv4Forwarding   = "netbird-rt-ipv4-forwarding"
	Ipv6Nat          = "netbird-rt-ipv6-nat"
	Ipv4Nat          = "netbird-rt-ipv4-nat"
	NatFormat        = "netbird-nat-%s"
	ForwardingFormat = "netbird-fwd-%s"
	Ipv6             = "ipv6"
	Ipv4             = "ipv4"
)

func genKey(format string, input string) string {
	return fmt.Sprintf(format, input)
}

func NewFirewall(parentCTX context.Context) firewallManager {
	ctx, cancel := context.WithCancel(parentCTX)

	if isIptablesSupported() {
		log.Debugf("iptables is supported")
		ipv4, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		ipv6, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)

		return &iptablesManager{
			ctx:        ctx,
			stop:       cancel,
			ipv4Client: ipv4,
			ipv6Client: ipv6,
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
