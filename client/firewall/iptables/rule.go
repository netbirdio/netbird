package iptables

// Rule to handle management of rules
type Rule struct {
	ruleNumber int
	specs      []string
	v6         bool
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() int {
	return r.ruleNumber
}
