package nftables

import (
	"net"

	"github.com/google/nftables"
)

// Rule to handle management of rules
type Rule struct {
	nftRule *nftables.Rule
	nftSet  *nftables.Set
	ruleID  string
	ip      net.IP
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.ruleID
}
