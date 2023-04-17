package nftables

import (
	"github.com/google/nftables"
)

// Rule to handle management of rules
type Rule struct {
	*nftables.Rule
	id string
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.id
}
