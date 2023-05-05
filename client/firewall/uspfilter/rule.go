package uspfilter

import (
	"net"

	"github.com/google/gopacket"
	fw "github.com/netbirdio/netbird/client/firewall"
)

// Rule to handle management of rules
type Rule struct {
	id         string
	ip         net.IP
	ipLayer    gopacket.LayerType
	protoLayer gopacket.LayerType
	direction  fw.Direction
	port       uint16
	drop       bool
	comment    string
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.id
}
