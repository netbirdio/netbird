package nftables

import (
	"net"

	"github.com/google/nftables"
)

// Rule to handle management of rules
type Rule struct {
	nftRule    *nftables.Rule
	mangleRule *nftables.Rule
	nftSet     *nftables.Set
	ruleID     string
	ip         net.IP
}

// GetRuleID returns the rule id
func (r *Rule) ID() string {
	return r.ruleID
}
