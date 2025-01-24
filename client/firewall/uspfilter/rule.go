package uspfilter

import (
	"net"

	"github.com/google/gopacket"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// Rule to handle management of rules
type Rule struct {
	id         string
	ip         net.IP
	ipLayer    gopacket.LayerType
	matchByIP  bool
	protoLayer gopacket.LayerType
	sPort      *firewall.Port
	dPort      *firewall.Port
	drop       bool
	comment    string

	udpHook func([]byte) bool
}

// GetRuleID returns the rule id
func (r *Rule) ID() string {
	return r.id
}
