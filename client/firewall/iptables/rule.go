package iptables

// Rule to handle management of rules
type Rule struct {
	id    string
	specs []string
	dst   bool
	v6    bool
}

// GetRuleID returns the rule id
func (r *Rule) GetRuleID() string {
	return r.id
}
