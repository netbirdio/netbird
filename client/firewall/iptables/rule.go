package iptables

import "github.com/netbirdio/netbird/client/firewall/manager"

// Rule to handle management of rules. Source set membership (when the
// rule was built against a shared hash:net ipset) is encoded in specs;
// DeleteFilterRule recovers it via findSets so the refcounter can drop
// the right reference.
type Rule struct {
	id          manager.RuleID
	specs       []string
	mangleSpecs []string
	chain       string
	v6          bool
}

// ID returns the rule id
func (r *Rule) ID() manager.RuleID {
	return r.id
}
