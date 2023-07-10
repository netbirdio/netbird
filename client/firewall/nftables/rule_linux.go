package nftables

import (
	"github.com/google/nftables"
)

// Rule to handle management of rules
type Rule struct {
	nftRule *nftables.Rule
	nftSet  *nftables.Set

	ruleID string
	ip     []byte
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.ruleID
}
