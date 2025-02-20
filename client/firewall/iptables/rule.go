package iptables

// Rule to handle management of rules
type Rule struct {
	ruleID    string
	ipsetName string

	specs       []string
	mangleSpecs []string
	ip          string
	chain       string
}

// GetRuleID returns the rule id
func (r *Rule) ID() string {
	return r.ruleID
}
